'use client'

import Link from 'next/link'
import Toggle from './Toggle'
import { usePathname } from 'next/navigation'
import { Activity } from 'lucide-react'
import { ThemeProvider } from 'next-themes'
import clsx from 'clsx'

const navigation = [
  { name: 'Flagged Accounts', href: '/flagged' },
]

export default function Navbar() {
  	const pathname = usePathname()
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
              				<div className="hidden md:flex space-x-4">
							{navigation.map((item) => (
								<Link
									key={item.name}
									href={item.href}
									className={clsx(
										'px-3 py-2 rounded-md text-sm font-medium transition-colors', 
										pathname.startsWith(item.href) ? 
											'bg-primary text-primary-foreground'
											: 'text-muted-foreground hover:text-foreground hover:bg-accent'
									)}
								>
									{item.name}
								</Link>
							))}
							</div>
 			           	</div>
            			<div className="flex items-center space-x-2">
                			<Toggle />
            			</div>
          			</div>
        		</div>
      		</nav>
    	</ThemeProvider>
  	)
} 