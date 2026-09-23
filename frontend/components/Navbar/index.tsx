'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import Toggle from './Toggle'
import { Activity, LogIn } from 'lucide-react'
import { ThemeProvider } from 'next-themes'
import { Button } from '@/components/ui/button'

export default function Navbar() {
	const [showLogin, setShowLogin] = useState(false)

	useEffect(() => {
		fetch('/auth/status')
			.then((res) => (res.ok ? res.json() : null))
			.then((data) => setShowLogin(Boolean(data?.login_available) && !data?.logged_in))
			.catch(() => setShowLogin(false))
	}, [])

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
							{showLogin && (
								<Button asChild size="sm">
									<a href="/auth/login">
										<LogIn className="h-4 w-4 mr-2" />
										Login
									</a>
								</Button>
							)}
            			</div>
          			</div>
        		</div>
      		</nav>
    	</ThemeProvider>
  	)
}