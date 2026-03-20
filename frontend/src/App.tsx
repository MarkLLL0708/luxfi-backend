import './App.css'
import { WalletConnect } from './components/WalletConnect'

function App() {
  return (
    <div className="app">
      <header className="app-header">
        <div className="app-header__logo">
          <span className="logo-text">LuxFi</span>
          <span className="logo-dot">Vault</span>
        </div>
        <WalletConnect />
      </header>

      <main className="app-main">
        <section className="hero-section">
          <h1 className="hero-title">
            Luxury Asset <span className="accent">Tokenization</span>
          </h1>
          <p className="hero-subtitle">
            Connect your wallet to access the LuxFi ecosystem on BNB Smart Chain
          </p>
        </section>
      </main>
    </div>
  )
}

export default App
