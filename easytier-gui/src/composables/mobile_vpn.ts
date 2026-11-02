import type { MobileTunConfig } from './backend'
import { addPluginListener } from '@tauri-apps/api/core'
import { Utils } from 'easytier-frontend-lib'
import {
  consume_vpn_tile_action,
  get_vpn_status,
  prepare_vpn,
  start_vpn,
  stop_vpn,
  type VpnTileAction,
} from 'tauri-plugin-vpnservice-api'
import { collectNetworkInfo, getConfig, getMobileTunConfig, listNetworkInstanceIds, setTunFd } from './backend'

interface vpnStatus {
  running: boolean
  ipv4Addrs: string[]
  routes: string[]
  dns: string | null | undefined
}

let vpnReconcileTimer: ReturnType<typeof setTimeout> | null = null
const VPN_RECONCILE_INTERVAL_MS = 2000
const VPN_RECONCILE_MAX_ATTEMPTS = 60

let vpnReconcileGeneration = 0
let vpnReconcileAttempts = 0
let vpnReconcileQueue: Promise<void> = Promise.resolve()
let vpnPermissionRequest: Promise<boolean> | null = null
let vpnTileActionHandler: ((action: VpnTileAction) => Promise<void>) | undefined
let vpnTileActionQueue: Promise<void> = Promise.resolve()
let vpnAttachedInstanceIds: string[] = []
let vpnStartingInstanceIds: string[] | undefined
let vpnStartingSnapshotId: string | undefined
let vpnAttachment: Promise<MobileTunConfig> | null = null
let vpnErrorHandler: ((error: string) => void) | undefined
let vpnMemberErrors = ''

export function setMobileVpnErrorHandler(handler?: (error: string) => void) {
  vpnErrorHandler = handler
}

function reportRejectedMembers(config: MobileTunConfig) {
  const errors = config.rejected.map(({ instance_id, error }) => `${instance_id}: ${error}`).sort().join('\n')
  if (errors && errors !== vpnMemberErrors)
    vpnErrorHandler?.(errors)
  vpnMemberErrors = errors
}

const curVpnStatus: vpnStatus = {
  running: false,
  ipv4Addrs: [],
  routes: [],
  dns: undefined,
}

export function setMobileVpnTileActionHandler(
  handler?: (action: VpnTileAction) => Promise<void>,
) {
  vpnTileActionHandler = handler
}

export async function consumePendingMobileVpnTileAction() {
  const handler = vpnTileActionHandler
  if (!handler) {
    return false
  }

  const action = (await consume_vpn_tile_action())?.action
  if (action !== 'start' && action !== 'stop') {
    return false
  }

  const run = vpnTileActionQueue
    .catch(error => console.error('previous VPN tile action failed', error))
    .then(() => handler(action))
  vpnTileActionQueue = run.catch(error => console.error('VPN tile action failed', error))
  await run
  return true
}

async function requestVpnPermissionOnce() {
  console.log('prepare vpn')
  const prepare_ret = await prepare_vpn()
  console.log('prepare vpn', JSON.stringify((prepare_ret)))
  if (prepare_ret?.errorMsg?.length) {
    throw new Error(prepare_ret.errorMsg)
  }

  const granted = prepare_ret?.granted ?? true
  if (!granted) {
    console.info('vpn permission request was denied or dismissed')
  }

  return granted
}

async function requestVpnPermission() {
  if (vpnPermissionRequest) {
    console.log('reuse pending vpn permission request')
    return await vpnPermissionRequest
  }

  const request = requestVpnPermissionOnce()
  vpnPermissionRequest = request
  try {
    return await request
  }
  finally {
    if (vpnPermissionRequest === request) {
      vpnPermissionRequest = null
    }
  }
}

function clearVpnReconcileTimer() {
  if (vpnReconcileTimer) {
    clearTimeout(vpnReconcileTimer)
    vpnReconcileTimer = null
  }
}

function beginVpnReconcile() {
  clearVpnReconcileTimer()
  vpnReconcileAttempts = 0
  vpnReconcileGeneration += 1
  return vpnReconcileGeneration
}

function isCurrentVpnReconcile(generation: number) {
  return vpnReconcileGeneration === generation
}

function scheduleVpnReconcile(generation: number, reason: string) {
  if (!isCurrentVpnReconcile(generation))
    return

  if (vpnReconcileAttempts >= VPN_RECONCILE_MAX_ATTEMPTS) {
    console.error(
      'vpn service reconcile stopped after maximum attempts',
      VPN_RECONCILE_MAX_ATTEMPTS,
      reason,
    )
    return
  }

  clearVpnReconcileTimer()
  vpnReconcileAttempts += 1
  console.log(
    'vpn service is not ready, retrying',
    JSON.stringify({
      attempt: vpnReconcileAttempts,
      maxAttempts: VPN_RECONCILE_MAX_ATTEMPTS,
      delayMs: VPN_RECONCILE_INTERVAL_MS,
      reason,
    }),
  )
  vpnReconcileTimer = setTimeout(() => {
    vpnReconcileTimer = null
    void enqueueVpnReconcile(generation)
  }, VPN_RECONCILE_INTERVAL_MS)
}

function resetVpnConfigStatus() {
  vpnAttachedInstanceIds = []
  curVpnStatus.ipv4Addrs = []
  curVpnStatus.routes = []
  curVpnStatus.dns = undefined
}

function syncVpnStatusFromNative(status: Awaited<ReturnType<typeof get_vpn_status>>) {
  curVpnStatus.running = status?.running ?? false
  if (!curVpnStatus.running) {
    resetVpnConfigStatus()
    return
  }

  curVpnStatus.ipv4Addrs = [...(status?.ipv4Addrs ?? [])].sort()
  curVpnStatus.routes = [...(status?.routes ?? [])].sort()
  curVpnStatus.dns = status?.dns ?? undefined
}

async function waitVpnStatus(target_status: boolean, timeout_sec: number) {
  const start_time = Date.now()
  while (curVpnStatus.running !== target_status) {
    if (Date.now() - start_time > timeout_sec * 1000) {
      throw new Error('wait vpn status timeout')
    }
    await new Promise(r => setTimeout(r, 50))
  }
}

async function detachTunFd() {
  // The host must not close the system FD while Native still owns a local
  // attachment. setTunFd(0) resolves only after the existing Factory/Native
  // detach path has really completed.
  await setTunFd(0)
}

async function doStopVpn(force = false) {
  const wasRunning = curVpnStatus.running
  if (!force && !wasRunning) {
    return
  }
  await detachTunFd()
  console.log('stop vpn')
  const stop_ret = await stop_vpn()
  console.log('stop vpn', JSON.stringify((stop_ret)))
  if (wasRunning) {
    await waitVpnStatus(false, 3)
  }

  resetVpnConfigStatus()
}

async function doStartVpn(
  instanceIds: string[],
  ipv4Addrs: string[],
  routes: string[],
  dns: string | undefined,
  snapshotId: string,
) {
  if (curVpnStatus.running) {
    return
  }

  vpnStartingInstanceIds = instanceIds
  vpnStartingSnapshotId = snapshotId
  vpnAttachment = null

  console.log('start vpn service', ipv4Addrs, routes, dns)
  const request = {
    snapshotId,
    ipv4Addrs,
    routes,
    dns,
    disallowedApplications: ['com.kkrainbow.easytier'],
    mtu: 1300,
  }

  let start_ret = await start_vpn(request)
  console.log('start vpn response', JSON.stringify(start_ret))
  if (start_ret?.errorMsg === 'need_prepare') {
    const granted = await requestVpnPermission()
    if (!granted) {
      throw new Error('vpn_permission_denied')
    }
    start_ret = await start_vpn(request)
    console.log('start vpn retry response', JSON.stringify(start_ret))
  }

  if (start_ret?.errorMsg?.length) {
    throw new Error(start_ret.errorMsg)
  }
  const actual = await waitVpnAttachment()

  // Status comparisons are order-insensitive; the plugin receives the
  // complete result in the order returned by the Controller.
  curVpnStatus.ipv4Addrs = [...ipv4Addrs].sort()
  curVpnStatus.routes = [...routes].sort()
  curVpnStatus.dns = dns
  vpnAttachedInstanceIds = [...actual.instance_ids].sort()
  if (JSON.stringify([...actual.instance_ids].sort()) !== JSON.stringify([...instanceIds].sort())
    || JSON.stringify([...actual.addresses].sort()) !== JSON.stringify([...ipv4Addrs].sort())
    || JSON.stringify([...actual.routes].sort()) !== JSON.stringify([...routes].sort())
    || (actual.dns ?? undefined) !== dns) {
    scheduleVpnReconcile(vpnReconcileGeneration, 'attachment_configuration_changed')
  }
}

async function waitVpnAttachment() {
  if (!vpnAttachment)
    await waitVpnStatus(true, 3)
  const actual = await vpnAttachment
  if (!actual?.instance_ids.length)
    throw new Error('no mobile TUN member was attached')
  return actual
}

async function onVpnServiceStart(payload: any) {
  console.log('vpn service start', JSON.stringify(payload))
  // The acknowledgement must originate from the same VPN configuration
  // request. Delayed callbacks from a previous start cannot acknowledge this one.
  if (!payload.snapshotId || payload.snapshotId !== vpnStartingSnapshotId)
    return
  curVpnStatus.running = true
  if (payload.fd) {
    vpnAttachment = setTunFd(payload.fd, vpnStartingInstanceIds, payload.snapshotId)
    await vpnAttachment.then(async (actual) => {
      reportRejectedMembers(actual)
      vpnAttachedInstanceIds = [...actual.instance_ids].sort()
      if (!actual.instance_ids.length)
        await doStopVpn(true)
    }).catch(async (e) => {
      console.error('set tun fd failed', e)
      vpnErrorHandler?.(String(e))
      await doStopVpn(true).catch(stopError => console.error('stop vpn after tun attach failure', stopError))
    })
  }
}

async function onVpnServiceStop(payload: any) {
  console.log('vpn service stop', JSON.stringify(payload))
  if (payload.snapshotId && payload.snapshotId !== vpnStartingSnapshotId)
    return
  // The plugin has already stopped its system VPN. Try to release any local
  // borrow, but do not turn a late Native cleanup failure into a stale
  // "running" status for an FD the host no longer owns.
  try {
    await detachTunFd()
  }
  catch (error) {
    console.error('detach tun fd after vpn service stop failed', error)
  }
  curVpnStatus.running = false
  resetVpnConfigStatus()
}

async function registerVpnServiceListener() {
  console.log('register vpn service listener')
  await addPluginListener(
    'vpnservice',
    'vpn_service_start',
    onVpnServiceStart,
  )

  await addPluginListener(
    'vpnservice',
    'vpn_service_stop',
    onVpnServiceStop,
  )

  await addPluginListener(
    'vpnservice',
    'vpn_tile_action',
    () => {
      void consumePendingMobileVpnTileAction().catch((error) => {
        console.error('consume VPN tile action failed', error)
      })
    },
  )
}

async function reconcileNetworkInstance(generation: number) {
  if (!isCurrentVpnReconcile(generation))
    return

  clearVpnReconcileTimer()

  let instances: Awaited<ReturnType<typeof findRunningTunInstances>>
  try {
    instances = await findRunningTunInstances()
  }
  catch (error) {
    console.warn('vpn service instance query failed', error)
    scheduleVpnReconcile(generation, 'instance_list_unavailable')
    return
  }

  if (!isCurrentVpnReconcile(generation))
    return

  if (!instances.length) {
    if (curVpnStatus.running) {
      try {
        await doStopVpn()
      }
      catch (error) {
        console.error('stop vpn service failed', error)
      }
    }
    return
  }

  // Network info is only a retry signal. It must not choose members, routes or
  // the exported addresses; those come from the Controller's complete table.
  let retryReason: string | undefined
  let networkInfoUnavailable = false

  for (const { instanceId: memberId, config } of instances) {
    let curNetworkInfo
    try {
      curNetworkInfo = (await collectNetworkInfo(memberId)).info.map[memberId]
    }
    catch (error) {
      console.warn('vpn service network info query failed', memberId, error)
      retryReason ??= 'network_info_query_failed'
      networkInfoUnavailable = true
      continue
    }

    if (!isCurrentVpnReconcile(generation))
      return

    if (!curNetworkInfo) {
      console.warn('vpn service network info unavailable', memberId)
      retryReason ??= 'network_info_unavailable'
      networkInfoUnavailable = true
      continue
    }

    if (curNetworkInfo.error_msg?.length) {
      console.warn('vpn service network failed', memberId, curNetworkInfo.error_msg)
      retryReason ??= 'network_failed'
      continue
    }

    const virtualIpv4 = curNetworkInfo.my_node_info?.virtual_ipv4
    const virtualIpv6 = curNetworkInfo.my_node_info?.virtual_ipv6
    const dhcp = config.dhcp || config.dhcpv6
    if (!virtualIpv4?.address?.addr && !virtualIpv6?.address) {
      if (!dhcp && !config.virtual_ipv4 && curNetworkInfo.my_node_info)
        continue
      retryReason ??= dhcp ? 'dhcp_address_unavailable' : 'static_address_unavailable'
      if (!dhcp)
        networkInfoUnavailable = true
      continue
    }

  }

  if (!isCurrentVpnReconcile(generation))
    return

  // The Controller decides which running TUN instances participate. The host
  // only supplies its running-instance scope and applies the complete result;
  // it must not pre-filter members from network-info or config flags here.
  const instanceIds = instances.map(({ instanceId }) => instanceId).sort()
  let config: MobileTunConfig
  try {
    config = await getMobileTunConfig(instanceIds)
  }
  catch (error) {
    console.error('mobile TUN configuration query failed', error)
    scheduleVpnReconcile(generation, 'tun_configuration_unavailable')
    return
  }
  if (!isCurrentVpnReconcile(generation))
    return
  reportRejectedMembers(config)

  // Keep the complete table's order for the system VPN request. Sorted copies
  // are only used to compare semantic content with the plugin's status.
  const addresses = [...config.addresses]
  const routes = [...config.routes]
  const dns = config.dns ?? undefined
  if (!addresses.length) {
    if (retryReason)
      scheduleVpnReconcile(generation, retryReason)
    if (curVpnStatus.running) {
      // A temporary network-info gap must not tear down a VPN whose native
      // routes may still be valid. Wait for the next notification/retry.
      if (networkInfoUnavailable)
        return
      try {
        await doStopVpn()
      }
      catch (error) {
        console.error('stop vpn service failed', error)
      }
    }
    return
  }

  if (retryReason)
    scheduleVpnReconcile(generation, retryReason)
  else
    vpnReconcileAttempts = 0
  const sortedAddresses = [...addresses].sort()
  const sortedRoutes = [...routes].sort()
  // A replacement runtime needs its own attachment even with identical OS routes.
  const membersChanged = JSON.stringify([...config.instance_ids].sort()) !== JSON.stringify(vpnAttachedInstanceIds)
  const configChanged
    = JSON.stringify(sortedAddresses) !== JSON.stringify(curVpnStatus.ipv4Addrs)
      || JSON.stringify(sortedRoutes) !== JSON.stringify(curVpnStatus.routes)
      || dns !== curVpnStatus.dns

  if (!curVpnStatus.running || configChanged || membersChanged) {
    if (curVpnStatus.running) {
      try {
        await doStopVpn()
      }
      catch (error) {
        console.error('stop vpn service failed', error)
      }
    }

    if (!isCurrentVpnReconcile(generation))
      return

    try {
      await doStartVpn([...config.instance_ids].sort(), addresses, routes, dns, config.snapshot_id)
      if (!isCurrentVpnReconcile(generation))
        await doStopVpn()
    }
    catch (error) {
      if (error instanceof Error && error.message === 'vpn_permission_denied') {
        console.info('vpn permission request was denied or dismissed')
        return
      }
      console.error('start vpn service failed', error)
    }
  }
}

function enqueueVpnTask(task: () => Promise<void>) {
  const run = vpnReconcileQueue
    .catch((e) => {
      console.error('previous vpn service reconcile failed', e)
    })
    .then(task)
  vpnReconcileQueue = run.catch((e) => {
    console.error('vpn service reconcile failed', e)
  })
  return run
}

function enqueueVpnReconcile(generation: number) {
  return enqueueVpnTask(() => reconcileNetworkInstance(generation))
}

export async function onNetworkInstanceChange(instanceId: string) {
  // A restarted instance keeps its ID but loses the previous runtime's TUN attachment.
  vpnAttachedInstanceIds = vpnAttachedInstanceIds.filter(id => id !== instanceId)
  await onNetworkInstancesChange()
}

export async function onNetworkInstancesChange() {
  await enqueueVpnReconcile(beginVpnReconcile())
}

export async function onNetworkInstanceUpdate(instanceId: string) {
  if (!instanceId)
    return
  await onNetworkInstancesChange()
}

async function isNoTunEnabled(instanceId: string | undefined) {
  if (!instanceId) {
    return false
  }
  return (await getConfig(instanceId)).no_tun ?? false
}

async function findRunningTunInstances() {
  const instanceIds = await listNetworkInstanceIds()
  const runningIds = (instanceIds.running_inst_ids ?? []).map(Utils.UuidToStr)
  const runningTunInstances = []

  for (const instanceId of runningIds) {
    const config = await getConfig(instanceId)
    if (config.no_tun)
      continue
    runningTunInstances.push({ instanceId, config })
  }

  return runningTunInstances
}

export async function initMobileVpnService() {
  await registerVpnServiceListener()
}

export async function prepareVpnService(instanceId: string) {
  if (await isNoTunEnabled(instanceId)) {
    return
  }

  await requestVpnPermission()
}

export async function syncMobileVpnService() {
  syncVpnStatusFromNative(await get_vpn_status())
  await onNetworkInstanceChange('')
}
