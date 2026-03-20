import { usePrivy, useSignMessage, useWallets } from '@privy-io/react-auth'
import { useCallback, useState } from 'react'

const API_BASE = 'https://luxfi-backend-production.up.railway.app/api/v1'

export function usePrivyAuth() {
  const { user, authenticated } = usePrivy()
  const { signMessage } = useSignMessage()
  const { wallets } = useWallets()
  const [isAuthenticating, setIsAuthenticating] = useState(false)
  const [authError, setAuthError] = useState<string | null>(null)

  const getWalletAddress = useCallback((): string | null => {
    if (!user) return null
    // Embedded wallet (for Google/email/SMS users)
    if (user.wallet?.address) return user.wallet.address
    // External wallet
    if (wallets.length > 0) return wallets[0].address
    return null
  }, [user, wallets])

  const isSmartWalletUser = useCallback((): boolean => {
    if (!user) return false
    return !!(user.google || user.email || user.phone)
  }, [user])

  const authenticate = useCallback(async () => {
    if (!authenticated || !user) return
    const walletAddress = getWalletAddress()
    if (!walletAddress) return

    setIsAuthenticating(true)
    setAuthError(null)

    try {
      // Step 1: Get nonce
      const nonceRes = await fetch(`${API_BASE}/auth/nonce`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ walletAddress }),
      })

      if (!nonceRes.ok) throw new Error('Failed to get nonce')
      const { nonce } = await nonceRes.json()

      // Step 2: Sign the nonce message
      let signature: string

      if (isSmartWalletUser()) {
        // Embedded wallet signing for Google/email/SMS users
        const result = await signMessage(
          { message: nonce },
          { address: walletAddress },
        )
        signature = result.signature
      } else {
        // External wallet signing
        const wallet = wallets.find(
          (w) => w.address.toLowerCase() === walletAddress.toLowerCase(),
        )
        if (!wallet) throw new Error('Wallet not found')
        const provider = await wallet.getEthereumProvider()
        signature = await provider.request({
          method: 'personal_sign',
          params: [nonce, walletAddress],
        })
      }

      // Step 3: Login with signature
      const loginRes = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ walletAddress, signature, nonce }),
      })

      if (!loginRes.ok) throw new Error('Authentication failed')
      const { token } = await loginRes.json()

      localStorage.setItem('luxfi_token', token)
      localStorage.setItem('luxfi_wallet', walletAddress)
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Authentication failed')
    } finally {
      setIsAuthenticating(false)
    }
  }, [authenticated, user, getWalletAddress, isSmartWalletUser, signMessage, wallets])

  const clearAuth = useCallback(() => {
    localStorage.removeItem('luxfi_token')
    localStorage.removeItem('luxfi_wallet')
  }, [])

  return {
    walletAddress: getWalletAddress(),
    isSmartWallet: isSmartWalletUser(),
    isAuthenticating,
    authError,
    authenticate,
    clearAuth,
  }
}
