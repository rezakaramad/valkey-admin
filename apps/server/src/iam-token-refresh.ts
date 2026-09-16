import { GlideClient, GlideClusterClient, ClosingError } from "@valkey/valkey-glide"
import { mintGcpAccessToken } from "./gcp-iam-provider"

// GCP OAuth2 access tokens live ~1 hour. Glide keeps existing connections
// authenticated after expiry, but new/reconnecting connections need a fresh
// token, so we re-mint and push it to every node connection well before expiry.
const REFRESH_INTERVAL_MS = 45 * 60 * 1000
// A refresh failure only logs and leaves the previous password in place. Since
// the token expires ~1h in, waiting a full interval could leave reconnects using
// an expired token; retry sooner so a fresh token lands well before expiry.
const RETRY_DELAY_MS = 5 * 60 * 1000

type RefreshableClient = GlideClient | GlideClusterClient

const refreshTimers = new Map<RefreshableClient, NodeJS.Timeout>()
const retryTimers = new Map<RefreshableClient, NodeJS.Timeout>()
// Clients whose current interval has already consumed its single retry.
const retryUsed = new Set<RefreshableClient>()

function clearRetry(client: RefreshableClient): void {
  const retry = retryTimers.get(client)
  if (retry) {
    clearTimeout(retry)
    retryTimers.delete(client)
  }
}

function scheduleRetry(
  client: RefreshableClient,
  label: string,
  useTLS: boolean,
  verifyTlsCertificate: boolean,
): void {
  // At most one retry per interval: skip if unregistered, already retried this
  // interval, or a retry is already pending.
  if (!refreshTimers.has(client) || retryUsed.has(client) || retryTimers.has(client)) return
  retryUsed.add(client)
  const retry = setTimeout(() => {
    retryTimers.delete(client)
    void refreshToken(client, label, useTLS, verifyTlsCertificate)
  }, RETRY_DELAY_MS)
  retry.unref?.()
  retryTimers.set(client, retry)
}

async function refreshToken(
  client: RefreshableClient,
  label: string,
  useTLS: boolean,
  verifyTlsCertificate: boolean,
): Promise<void> {
  try {
    const token = await mintGcpAccessToken(useTLS, verifyTlsCertificate)
    await client.updateConnectionPassword(token, true)
    // Success: drop any retry queued by an earlier failure.
    clearRetry(client)
  } catch (error) {
    if (error instanceof ClosingError) {
      unregisterGcpTokenRefresh(client)
      return
    }
    console.error(`Error refreshing GCP IAM token for ${label}:`, error)
    scheduleRetry(client, label, useTLS, verifyTlsCertificate)
  }
}

// Rotate the connection password for a gcp-iam client on a timer.
// Keyed by the client instance so shared cluster clients are only scheduled once; the timer
// self-clears once the client is closed (updateConnectionPassword throws ClosingError),
// so callers do not have to unregister at every close site.
export function registerGcpTokenRefresh(
  client: RefreshableClient,
  label: string,
  useTLS: boolean,
  verifyTlsCertificate: boolean,
): void {
  if (refreshTimers.has(client)) return

  const timer = setInterval(() => {
    // Each interval gets a fresh retry budget.
    retryUsed.delete(client)
    void refreshToken(client, label, useTLS, verifyTlsCertificate)
  }, REFRESH_INTERVAL_MS)

  // Do not keep the process alive solely for the refresh timer.
  timer.unref?.()
  refreshTimers.set(client, timer)
}

export function unregisterGcpTokenRefresh(client: RefreshableClient): void {
  const timer = refreshTimers.get(client)
  if (timer) {
    clearInterval(timer)
    refreshTimers.delete(client)
  }
  clearRetry(client)
  retryUsed.delete(client)
}
