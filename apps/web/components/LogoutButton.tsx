"use client";

import { api } from '../lib/apiClient';

export function LogoutButton() {
  async function onClick(e: React.MouseEvent) {
    e.preventDefault();
    await api('/auth/logout', { method: 'POST' });
    location.href = '/';
  }
  return <button onClick={onClick}>Logout</button>;
}
