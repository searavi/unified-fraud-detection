'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import Toggle from './Toggle'
import { Activity, LogIn, LogOut } from 'lucide-react'
import { ThemeProvider } from 'next-themes'
import { Button } from '@/components/ui/button'

export default function Navbar() {
	const [authStatus, setAuthStatus] = useState<{ loginAvailable: boolean; loggedIn: boolean } | null>(null)

	const checkAuthStatus = () => {
		fetch('/auth/status')
			.then((res) => (res.ok ? res.json() : null))
			.then((data) =>
				setAuthStatus({
					loginAvailable: Boolean(data?.login_available),
					loggedIn: Boolean(data?.logged_in),
				})
			)
			.catch(() => setAuthStatus({ loginAvailable: false, loggedIn: false }))
	}

	useEffect(() => {
		checkAuthStatus()
	}, [])

	const handleLogout = async () => {
		await fetch('/auth/logout', { method: 'POST' })
		// Reload rather than just re-checking status: any page-local data fetched while logged
		// in (e.g. the flagged list) needs to re-run its own gate too, not just the navbar.
		window.location.href = '/'
	}

  	return (
    	<ThemeProvider attribute='data-theme' enableSystem>
      		<nav className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        		<div className="container mx-auto px-4">
          			<div className="flex h-16 items-center justify-between">
            			<div className="flex items-center space-x-4">
              				<Link href="/" className="flex items-center space-x-2">
                				<Activity className="h-6 w-6" />
                				<span className="font-bold">Fraud Detection</span>
              				</Link>
 			           	</div>
            			<div className="flex items-center space-x-2">
                			<Toggle />
							{authStatus?.loginAvailable && !authStatus.loggedIn && (
								<Button asChild size="sm">
									<a href="/auth/login">
										<LogIn className="h-4 w-4 mr-2" />
										Login
									</a>
								</Button>
							)}
							{authStatus?.loginAvailable && authStatus.loggedIn && (
								<Button variant="outline" size="sm" onClick={handleLogout}>
									<LogOut className="h-4 w-4 mr-2" />
									Logout
								</Button>
							)}
            			</div>
          			</div>
        		</div>
      		</nav>
    	</ThemeProvider>
  	)
}