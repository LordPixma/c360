import React from 'react'
import { createRoot } from 'react-dom/client'
import LoginPage from './pages/LoginPage'
import './styles/global.scss'
import AppHeader from './components/AppHeader'
import { IdentityProvider } from './context/IdentityContext'

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <IdentityProvider>
      <AppHeader />
      <LoginPage />
    </IdentityProvider>
  </React.StrictMode>
)
