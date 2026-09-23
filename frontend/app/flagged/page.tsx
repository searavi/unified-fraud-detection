'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Skeleton } from '@/components/ui/skeleton'
import Link from 'next/link'
import { 
    Eye, 
    Search, 
    AlertTriangle, 
    Clock, 
    Shield,
    ChevronLeft,
    ChevronRight,
    Building,
    User,
    Calendar,
    TrendingUp,
    RefreshCw,
    CheckCircle,
    XCircle
} from 'lucide-react'
import useSWR from 'swr'

interface FlaggedAccount {
    account_id: string
    user_id: string
    account_holder: string
    account_type?: string
    risk_score: number
    flag_reason: string
    flagged_date: string
    status: string
    suspicious_transactions?: number
    total_flagged_amount?: number
    account_count?: number
    features?: Record<string, any>
    risk_factors?: string[]
    account_predictions?: Array<{ account_id: string; risk_score: number }>
    highest_risk_account_id?: string
}

interface FlaggedStats {
    total_flagged: number
    pending_review: number
    under_investigation: number
    confirmed_fraud: number
    cleared: number
    avg_risk_score: number
    total_flagged_amount: number
}

interface FlaggedResponse {
    accounts: FlaggedAccount[]
    total: number
    total_pages: number
}

const statusConfig = {
    pending_review: { 
        label: 'Pending Review', 
        color: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
        icon: Clock
    },
    under_investigation: { 
        label: 'Under Investigation', 
        color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
        icon: Shield
    },
    confirmed_fraud: { 
        label: 'Confirmed Fraud', 
        color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
        icon: XCircle
    },
    cleared: { 
        label: 'Cleared', 
        color: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
        icon: CheckCircle
    }
}

export default function FlaggedAccountsPage() {
    const [filter, setFilter] = useState<'all' | 'pending_review' | 'under_investigation'>('all')
    const [searchQuery, setSearchQuery] = useState('')
    const [debouncedSearch, setDebouncedSearch] = useState('')
    const [page, setPage] = useState(1)
    const pageSize = 20

    // null = still checking; only decide what to render once this resolves, to avoid a flash
    // of the list before we know whether a login is required.
    const [authStatus, setAuthStatus] = useState<{ loginAvailable: boolean; loggedIn: boolean } | null>(null)
    useEffect(() => {
        fetch('/auth/status')
            .then((res) => (res.ok ? res.json() : null))
            .then((data) =>
                setAuthStatus({
                    loginAvailable: Boolean(data?.login_available),
                    loggedIn: Boolean(data?.logged_in),
                })
            )
            .catch(() => setAuthStatus({ loginAvailable: false, loggedIn: false }))
    }, [])

    // No login configured at all (local dev) -> show freely, same as today. Login configured but
    // not yet logged in -> gate the list. Logged in -> show freely.
    const canViewList = authStatus !== null && (!authStatus.loginAvailable || authStatus.loggedIn)

    // Build SWR key for accounts list
    const accountsParams = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString()
    })
    if (filter !== 'all') accountsParams.append('status', filter)
    if (debouncedSearch) accountsParams.append('search', debouncedSearch)

    // Passing null as the key skips the fetch entirely until we know the user is allowed to see
    // this data — avoids fetching (and briefly caching) it before the login gate resolves.
    const { data: accountsData, isLoading: loading, mutate: mutateAccounts } = useSWR<FlaggedResponse>(
        canViewList ? `/api/flagged-accounts?${accountsParams}` : null,
        { keepPreviousData: true }
    )
    const { data: stats, isLoading: statsLoading, mutate: mutateStats } = useSWR<FlaggedStats>(
        canViewList ? '/api/flagged-accounts/stats' : null,
        // Always refetch on mount rather than trusting a possibly-stale cached value — this is
        // the count that goes stale after starting an investigation elsewhere and navigating back.
        { revalidateOnMount: true }
    )

    const accounts = accountsData?.accounts ?? []
    const total = accountsData?.total ?? 0
    const totalPages = accountsData?.total_pages ?? 1

    const handleFilterChange = (newFilter: typeof filter) => {
        setFilter(newFilter)
        setPage(1)
    }

    const handleRefresh = () => {
        mutateAccounts()
        mutateStats()
    }

    // Debounce search
    const handleSearchChange = (value: string) => {
        setSearchQuery(value)
        // Debounce the actual SWR key update
        const timer = setTimeout(() => {
            setDebouncedSearch(value)
            setPage(1)
        }, 300)
        return () => clearTimeout(timer)
    }

    if (authStatus === null) {
        return (
            <div className="space-y-6 flex flex-col grow">
                <Skeleton className="h-10 w-64" />
                <div className="grid gap-4 md:grid-cols-4">
                    {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24" />)}
                </div>
            </div>
        )
    }

    if (!canViewList) {
        return (
            <div className="flex flex-col grow items-center justify-center text-center py-12">
                <Shield className="h-12 w-12 text-muted-foreground mb-4" />
                <h1 className="text-2xl font-bold mb-2">Login required</h1>
                <p className="text-muted-foreground max-w-md">
                    Use the Login button above to view flagged accounts.
                </p>
            </div>
        )
    }

    return (
        <div className="space-y-6 flex flex-col grow">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Flagged Accounts</h1>
                    <p className="text-muted-foreground">Review and process high-risk accounts flagged for potential fraud</p>
                </div>
                <Button variant="outline" onClick={handleRefresh} disabled={loading}>
                    <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                    Refresh
                </Button>
            </div>

            {/* Stats Section */}
            <div className="grid gap-4 md:grid-cols-4">
                {statsLoading ? (
                    <>
                        {[...Array(4)].map((_, i) => (
                            <Card key={i}>
                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                    <Skeleton className="h-4 w-24" />
                                </CardHeader>
                                <CardContent>
                                    <Skeleton className="h-8 w-16 mb-1" />
                                    <Skeleton className="h-3 w-32" />
                                </CardContent>
                            </Card>
                        ))}
                    </>
                ) : stats ? (
                    <>
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">Pending Review</CardTitle>
                                <AlertTriangle className="h-4 w-4 text-amber-500" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold text-amber-600">{stats.pending_review.toLocaleString()}</div>
                                <p className="text-xs text-muted-foreground">Accounts awaiting analyst review</p>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">Under Investigation</CardTitle>
                                <Shield className="h-4 w-4 text-blue-500" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold">{stats.under_investigation.toLocaleString()}</div>
                                <p className="text-xs text-muted-foreground">Currently being investigated</p>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">Confirmed Fraud</CardTitle>
                                <XCircle className="h-4 w-4 text-red-500" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold text-red-600">{stats.confirmed_fraud.toLocaleString()}</div>
                                <p className="text-xs text-muted-foreground">Marked as fraudulent</p>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">Cleared</CardTitle>
                                <CheckCircle className="h-4 w-4 text-green-500" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold text-green-600">{stats.cleared.toLocaleString()}</div>
                                <p className="text-xs text-muted-foreground">Verified as legitimate</p>
                            </CardContent>
                        </Card>
                    </>
                ) : (
                    <div className="col-span-4 text-center py-4 text-muted-foreground">
                        No stats available. Run a detection job to populate data.
                    </div>
                )}
            </div>

            {/* Main Content */}
            <Card className="grow flex flex-col">
                <CardHeader className="gap-4">
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                        <CardTitle>Accounts Requiring Review</CardTitle>
                        <Tabs value={filter} onValueChange={(v) => handleFilterChange(v as typeof filter)}>
                            <TabsList>
                                <TabsTrigger value="all">All</TabsTrigger>
                                <TabsTrigger value="pending_review">Pending</TabsTrigger>
                                <TabsTrigger value="under_investigation">Investigating</TabsTrigger>
                            </TabsList>
                        </Tabs>
                    </div>
                    <div className="flex gap-2">
                        <div className="relative flex-1">
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                                placeholder="Search by account holder or ID..."
                                className="pl-9"
                                value={searchQuery}
                                onChange={(e) => handleSearchChange(e.target.value)}
                            />
                        </div>
                    </div>
                </CardHeader>
                <CardContent className="grow overflow-x-auto flex flex-col">
                    {loading ? (
                        <div className="space-y-3">
                            {[...Array(5)].map((_, i) => (
                                <div key={i} className="border rounded-lg p-4">
                                    <div className="flex items-center gap-3">
                                        <Skeleton className="h-10 w-10 rounded-full" />
                                        <div className="flex-1">
                                            <Skeleton className="h-5 w-48 mb-2" />
                                            <Skeleton className="h-4 w-64" />
                                        </div>
                                        <Skeleton className="h-10 w-24" />
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : accounts.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 text-center">
                            <Shield className="h-12 w-12 text-muted-foreground mb-4" />
                            <h3 className="text-lg font-semibold mb-2">No Flagged Accounts</h3>
                            <p className="text-muted-foreground max-w-md">
                                {searchQuery || filter !== 'all' 
                                    ? 'No accounts match your search criteria. Try adjusting your filters.'
                                    : 'No accounts have been flagged yet. Run a detection job from the Admin panel to identify high-risk accounts.'}
                            </p>
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {accounts.map((account) => {
                                const status = statusConfig[account.status as keyof typeof statusConfig] || statusConfig.pending_review
                                const StatusIcon = status.icon
                                return (
                                    <div
                                        key={account.account_id}
                                        className="border rounded-lg p-4 hover:bg-muted/50 transition-colors"
                                    >
                                        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                                            {/* Left Section - Account Info */}
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-start gap-3">
                                                    <div className="p-2 rounded-full bg-destructive/10 text-destructive">
                                                        <AlertTriangle className="h-5 w-5" />
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <div className="flex items-center gap-2 flex-wrap">
                                                            <h3 className="font-semibold text-lg">{account.account_holder}</h3>
                                                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${status.color}`}>
                                                                <StatusIcon className="h-3 w-3" />
                                                                {status.label}
                                                            </span>
                                                        </div>
                                                        <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1 flex-wrap">
                                                            <span className="flex items-center gap-1">
                                                                <Building className="h-3.5 w-3.5" />
                                                                {account.account_id}
                                                            </span>
                                                            <span className="flex items-center gap-1">
                                                                <User className="h-3.5 w-3.5" />
                                                                {account.user_id}
                                                            </span>
                                                            <span className="flex items-center gap-1">
                                                                <Calendar className="h-3.5 w-3.5" />
                                                                Flagged {new Date(account.flagged_date).toLocaleDateString()}
                                                            </span>
                                                        </div>
                                                        <p className="text-sm mt-2 text-muted-foreground">
                                                            <span className="font-medium text-foreground">Reason:</span> {account.flag_reason}
                                                        </p>
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Middle Section - Risk Metrics */}
                                            <div className="flex items-center gap-6 lg:gap-8">
                                                <div className="text-center">
                                                    <div className="flex items-center gap-1 justify-center">
                                                        <TrendingUp className="h-4 w-4 text-destructive" />
                                                        <span className="text-2xl font-bold text-destructive">{account.risk_score.toFixed(1)}</span>
                                                    </div>
                                                    <p className="text-xs text-muted-foreground">Risk Score</p>
                                                </div>
                                                <div className="text-center">
                                                    <p className="text-2xl font-bold text-destructive">
                                                        {account.account_predictions?.filter(p => p.risk_score >= 50).length ?? 0}
                                                    </p>
                                                    <p className="text-xs text-muted-foreground">High Risk Accounts</p>
                                                </div>
                                            </div>

                                            {/* Right Section - Action */}
                                            <div className="flex items-center">
                                                <Link href={`/flagged/${account.user_id}`}>
                                                    <Button>
                                                        <Eye className="h-4 w-4 mr-2" />
                                                        Review
                                                    </Button>
                                                </Link>
                                            </div>
                                        </div>
                                    </div>
                                )
                            })}
                        </div>
                    )}
                </CardContent>
                <CardFooter className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">
                        Showing {accounts.length} of {total} flagged accounts
                    </p>
                    <div className="flex items-center gap-2">
                        <Button 
                            variant="outline" 
                            size="sm" 
                            disabled={page <= 1 || loading}
                            onClick={() => setPage(p => p - 1)}
                        >
                            <ChevronLeft className="h-4 w-4" />
                            Previous
                        </Button>
                        <span className="text-sm text-muted-foreground px-2">
                            Page {page} of {totalPages}
                        </span>
                        <Button 
                            variant="outline" 
                            size="sm" 
                            disabled={page >= totalPages || loading}
                            onClick={() => setPage(p => p + 1)}
                        >
                            Next
                            <ChevronRight className="h-4 w-4" />
                        </Button>
                    </div>
                </CardFooter>
            </Card>
        </div>
    )
}
