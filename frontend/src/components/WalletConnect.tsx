import { usePrivy } from '@privy-io/react-auth'
import { useEffect } from 'react'
import { usePrivyAuth } from '../hooks/usePrivyAuth'

function truncateAddress(address: string): string {
  return `${address.slice(0, 6)}...${address.slice(-4)}`
}

export function WalletConnect() {
  const { login, logout, authenticated, ready } = usePrivy()
  const { walletAddress, isSmartWallet, isAuthenticating, authenticate, clearAuth } =
    usePrivyAuth()

  // Trigger backend auth after Privy login
  useEffect(() => {
    if (authenticated && walletAddress && !localStorage.getItem('luxfi_token')) {
      authenticate()
    }
  }, [authenticated, walletAddress, authenticate])

  const handleLogout = async () => {
    clearAuth()
    await logout()
  }

  if (!ready) {
    return (
      <button className="wallet-btn wallet-btn--loading" disabled>
        Loading...
      </button>
    )
  }

  if (!authenticated) {
    return (
      <button className="wallet-btn wallet-btn--connect" onClick={login}>
        Connect Wallet
      </button>
    )
  }

  return (
    <div className="wallet-connected">
      <div className="wallet-badges">
        <span className="badge badge--bsc">BSC</span>
        {isSmartWallet && <span className="badge badge--smart">Smart Wallet</span>}
      </div>
      <span className="wallet-address">
        {walletAddress ? truncateAddress(walletAddress) : '...'}
      </span>
      {isAuthenticating && <span className="wallet-status">Signing in...</span>}
      <button className="wallet-btn wallet-btn--logout" onClick={handleLogout}>
        Disconnect
      </button>
    </div>
  )
}
