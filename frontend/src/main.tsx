import React from 'react'
import { createRoot } from 'react-dom/client'
import LoginPage from './pages/LoginPage'
import './styles/global.scss'
import AppHeader from './components/AppHeader'

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
  <AppHeader />
    <LoginPage />
  </React.StrictMode>
)
