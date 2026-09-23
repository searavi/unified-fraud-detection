'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Skeleton } from '@/components/ui/skeleton'
import { 
    ArrowLeft,
    AlertTriangle,
    Building,
    User,
    Calendar,
    Clock,
    DollarSign,
    MapPin,
    CreditCard,
    Activity,
    ExternalLink,
    TrendingUp,
    Shield,
    Smartphone,
    Globe,
    Brain,
    PlayCircle,
    StopCircle,
    RefreshCw,
    XCircle,
    Loader2
} from 'lucide-react'
import ReviewWorkflow from '@/components/Flagged/Details/ReviewWorkflow'
import GraphVisualization from '@/components/Flagged/Details/GraphVisualization'
import { InvestigationReport } from '@/components/Flagged/Details/InvestigationReport'
import PerformanceMetricsPanel from '@/components/Flagged/Details/PerformanceMetricsPanel'
import { useInvestigation } from '@/hooks/useInvestigation'
import { useAccountData } from '@/hooks/useAccountData'
import { formatCurrency } from '@/lib/utils'

const riskBadge = (severity: string) => {
    const colors = {
        high: 'bg-red-100 text-red-700 border-red-200',
        medium: 'bg-amber-100 text-amber-700 border-amber-200',
        low: 'bg-blue-100 text-blue-700 border-blue-200'
    }
    return colors[severity as keyof typeof colors] || colors.low
}

// Loading skeleton for the page
function LoadingSkeleton() {
    return (
        <div className="space-y-6">
            {/* Header skeleton */}
            <div className="flex items-start justify-between">
                <div>
                    <Skeleton className="h-4 w-40 mb-2" />
                    <div className="flex items-center gap-3">
                        <Skeleton className="h-12 w-12 rounded-full" />
                        <div>
                            <Skeleton className="h-8 w-64 mb-2" />
                            <Skeleton className="h-4 w-48" />
                        </div>
                    </div>
                </div>
                <div className="flex gap-2">
                    <Skeleton className="h-10 w-40" />
                    <Skeleton className="h-10 w-36" />
                </div>
            </div>

            {/* Alert banner skeleton */}
            <Skeleton className="h-24 w-full" />

            {/* Main content skeleton */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 space-y-6">
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-80 w-full" />
                    <div className="grid grid-cols-2 gap-6">
                        <Skeleton className="h-60" />
                        <Skeleton className="h-60" />
                    </div>
                </div>
                <Skeleton className="h-96" />
            </div>
        </div>
    )
}

// Error state component
function ErrorState({ error, onRetry }: { error: string; onRetry: () => void }) {
    return (
        <div className="flex flex-col items-center justify-center min-h-[400px] space-y-4">
            <div className="p-4 rounded-full bg-red-100 text-red-600">
                <AlertTriangle className="h-8 w-8" />
            </div>
            <h2 className="text-xl font-semibold text-slate-900">Failed to Load Account Data</h2>
            <p className="text-slate-500 text-center max-w-md">{error}</p>
            <Button onClick={onRetry} variant="outline" className="border-slate-300">
                <RefreshCw className="h-4 w-4 mr-2" />
                Try Again
            </Button>
        </div>
    )
}

export default function FlaggedAccountDetailsPage() {
    const params = useParams()
    const accountId = params.id as string
    const [currentStep, setCurrentStep] = useState(0)
    const [activeTab, setActiveTab] = useState('overview')
    const [loadedExisting, setLoadedExisting] = useState(false)
    
    // Fetch real account data
    const { data: account, loading, error, refetch } = useAccountData(accountId)
    
    // Investigation hook
    const investigation = useInvestigation()

    // Load existing investigation on mount
    useEffect(() => {
        const loadExisting = async () => {
            if (account?.user_id && investigation.status === 'idle' && !loadedExisting) {
                setLoadedExisting(true)
                const found = await investigation.loadExistingInvestigation(account.user_id)
                if (found) {
                    console.log('[Page] Loaded existing investigation')
                }
            }
        }
        loadExisting()
    }, [account?.user_id, investigation.status, loadedExisting])

    const handleStartInvestigation = () => {
        if (account) {
            investigation.startInvestigation(account.user_id)
            setActiveTab('investigation')
        }
    }

    const handleStopInvestigation = () => {
        investigation.stopInvestigation()
    }

    const handleEnableWorkflowPolicy = () => {
        if (account) {
            investigation.enableWorkflowPolicy(account.user_id)
            setActiveTab('investigation')
        }
    }

    // Loading state
    if (loading) {
        return <LoadingSkeleton />
    }

    // Error state
    if (error || !account) {
        return <ErrorState error={error || 'Account not found'} onRetry={refetch} />
    }

    return (
        <div className="space-y-6 bg-slate-50 min-h-screen -m-6 p-6">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <Link href="/flagged" className="flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 mb-2">
                        <ArrowLeft className="h-4 w-4" />
                        Back to Flagged Accounts
                    </Link>
                    <div className="flex items-center gap-3">
                        <div className="p-3 rounded-full bg-red-100 text-red-600">
                            <AlertTriangle className="h-6 w-6" />
                        </div>
                        <div>
                            <h1 className="text-3xl font-bold tracking-tight text-slate-900">{account.account_holder}</h1>
                            <div className="flex items-center gap-3 text-slate-500 mt-1">
                                <span className="flex items-center gap-1">
                                    <Building className="h-4 w-4" />
                                    {account.id}
                                </span>
                                <span>•</span>
                                <span className="flex items-center gap-1">
                                    <CreditCard className="h-4 w-4" />
                                    {account.bank_name} - {account.account_type}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    {/* Refresh Button */}
                    <Button variant="outline" size="icon" onClick={refetch} title="Refresh data" className="border-slate-300">
                        <RefreshCw className="h-4 w-4" />
                    </Button>
                    {/* Investigation Button */}
                    {investigation.status === 'idle' || investigation.status === 'completed' || investigation.status === 'error' ? (
                        <Button 
                            onClick={handleStartInvestigation}
                            className="bg-indigo-600 hover:bg-indigo-700 text-white"
                        >
                            <Brain className="h-4 w-4 mr-2" />
                            Start AI Investigation
                        </Button>
                    ) : (
                        <Button 
                            onClick={handleStopInvestigation}
                            variant="destructive"
                        >
                            <StopCircle className="h-4 w-4 mr-2" />
                            Stop Investigation
                        </Button>
                    )}
                    <Link href={`/users/${account.user_id}`}>
                        <Button variant="outline" className="border-slate-300 text-slate-700 hover:bg-slate-50">
                            <User className="h-4 w-4 mr-2" />
                            View User Profile
                            <ExternalLink className="h-3 w-3 ml-2" />
                        </Button>
                    </Link>
                </div>
            </div>

            {/* Alert Banner */}
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-start gap-3">
                    <AlertTriangle className="h-5 w-5 text-red-600 mt-0.5" />
                    <div>
                        <h3 className="font-semibold text-red-800">
                            {account.risk_score >= 70 ? 'High Risk Alert' : 
                             account.risk_score >= 40 ? 'Medium Risk Alert' : 'Under Review'}
                        </h3>
                        <p className="text-sm text-red-700 mt-1">{account.flag_reason}</p>
                        <p className="text-xs text-red-600 mt-2">
                            Flagged on {new Date(account.flagged_date).toLocaleString()}
                        </p>
                    </div>
                </div>
            </div>

            {/* AI Investigation Error Banner */}
            {investigation.status === 'error' && investigation.error && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                        <XCircle className="h-5 w-5 text-red-600 mt-0.5" />
                        <div className="flex-1">
                            <h3 className="font-semibold text-red-800">AI Investigation Failed</h3>
                            <p className="text-sm text-red-700 mt-1">{investigation.error}</p>
                            {(investigation.policyAction.status === 'failed' || investigation.policyAction.status === 'propagating') && investigation.policyAction.message && (
                                <p className={`text-sm font-medium mt-2 ${investigation.policyAction.status === 'failed' ? 'text-red-800' : 'text-slate-600'}`}>
                                    {investigation.policyAction.message}
                                </p>
                            )}
                            {investigation.errorCode === 'hitl_policy_missing' && (
                                <Button
                                    onClick={handleEnableWorkflowPolicy}
                                    disabled={investigation.policyAction.status === 'enabling' || investigation.policyAction.status === 'propagating'}
                                    size="sm"
                                    className="mt-3 bg-indigo-600 hover:bg-indigo-700 text-white"
                                >
                                    {investigation.policyAction.status === 'enabling' ? (
                                        <>
                                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                            Enabling workflow execution...
                                        </>
                                    ) : investigation.policyAction.status === 'propagating' ? (
                                        <>
                                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                            Waiting for policy to propagate...
                                        </>
                                    ) : (
                                        'Enable Workflow Execution'
                                    )}
                                </Button>
                            )}
                            {investigation.errorCode === 'not_logged_in' && (
                                <Button
                                    asChild
                                    size="sm"
                                    className="mt-3 bg-indigo-600 hover:bg-indigo-700 text-white"
                                >
                                    <a href="/auth/login">Log in</a>
                                </Button>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Left Column - Account Details */}
                <div className="lg:col-span-2 space-y-6">
                    <Tabs value={activeTab} onValueChange={setActiveTab}>
                        <TabsList className="grid w-full grid-cols-6 bg-white border border-slate-200">
                            <TabsTrigger value="overview" className="data-[state=active]:bg-indigo-50 data-[state=active]:text-indigo-700">Overview</TabsTrigger>
                            <TabsTrigger value="investigation" className="relative data-[state=active]:bg-indigo-50 data-[state=active]:text-indigo-700">
                                Investigation
                                {(investigation.status === 'running' || investigation.status === 'connecting') && (
                                    <span className="absolute -top-1 -right-1 w-2 h-2 bg-indigo-500 rounded-full animate-pulse" />
                                )}
                            </TabsTrigger>
                            <TabsTrigger value="graph" className="data-[state=active]:bg-indigo-50 data-[state=active]:text-indigo-700">Graph</TabsTrigger>
                            <TabsTrigger value="transactions" className="data-[state=active]:bg-indigo-50 data-[state=active]:text-indigo-700">Transactions</TabsTrigger>
                            <TabsTrigger value="devices" className="data-[state=active]:bg-indigo-50 data-[state=active]:text-indigo-700">Devices</TabsTrigger>
                            <TabsTrigger value="activity" className="data-[state=active]:bg-indigo-50 data-[state=active]:text-indigo-700">Activity</TabsTrigger>
                        </TabsList>

                        <TabsContent value="overview" className="space-y-6 mt-6">
                            {/* Risk Score Card */}
                            <Card className="bg-white border-slate-200 shadow-sm">
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2 text-slate-900">
                                        <TrendingUp className="h-5 w-5 text-red-600" />
                                        Risk Analysis
                                    </CardTitle>
                                    <CardDescription className="text-slate-500">
                                        Breakdown of risk factors contributing to this flag
                                    </CardDescription>
                                </CardHeader>
                                <CardContent>
                                    <div className="flex items-center gap-6 mb-6">
                                        <div className="text-center">
                                            <div className="text-5xl font-bold text-red-600">{Math.round(account.risk_score)}</div>
                                            <p className="text-sm text-slate-500">Overall Risk Score</p>
                                        </div>
                                        <div className="flex-1">
                                            <div className="h-4 bg-slate-100 rounded-full overflow-hidden">
                                                <div 
                                                    className="h-full bg-gradient-to-r from-amber-500 via-orange-500 to-red-500 transition-all"
                                                    style={{ width: `${Math.min(100, account.risk_score)}%` }}
                                                />
                                            </div>
                                            <div className="flex justify-between text-xs text-slate-500 mt-1">
                                                <span>Low (0-25)</span>
                                                <span>Medium (25-70)</span>
                                                <span>High (70-100)</span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="space-y-3">
                                        {account.risk_factors.length > 0 ? (
                                            account.risk_factors.map((factor, idx) => (
                                                <div key={idx} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg border border-slate-100">
                                                    <div className="flex items-center gap-3">
                                                        <span className={`px-2 py-0.5 rounded text-xs font-medium border ${riskBadge(factor.severity)}`}>
                                                            {factor.severity.toUpperCase()}
                                                        </span>
                                                        <span className="text-sm text-slate-700">{factor.factor}</span>
                                                    </div>
                                                    <span className="font-semibold text-slate-900">+{factor.score}</span>
                                                </div>
                                            ))
                                        ) : (
                                            <div className="text-center text-slate-500 py-4">
                                                No specific risk factors identified
                                            </div>
                                        )}
                                    </div>
                                </CardContent>
                            </Card>

                            {/* Account Holder Info */}
                            <Card className="bg-white border-slate-200 shadow-sm">
                                <CardHeader>
                                    <CardTitle className="text-lg flex items-center gap-2 text-slate-900">
                                        <User className="h-5 w-5 text-slate-600" />
                                        Account Holder
                                    </CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                        <div>
                                            <span className="text-slate-500 text-sm">Name</span>
                                            <p className="font-medium text-slate-900">{account.user.name}</p>
                                        </div>
                                        <div>
                                            <span className="text-slate-500 text-sm">Email</span>
                                            <p className="font-medium text-sm text-slate-900">{account.user.email}</p>
                                        </div>
                                        <div>
                                            <span className="text-slate-500 text-sm">Phone</span>
                                            <p className="font-medium text-slate-900">{account.user.phone}</p>
                                        </div>
                                        <div>
                                            <span className="text-slate-500 text-sm">Location</span>
                                            <p className="font-medium text-slate-900">{account.user.location}</p>
                                        </div>
                                        {account.user.signup_date && (
                                            <div>
                                                <span className="text-slate-500 text-sm">Member Since</span>
                                                <p className="font-medium text-slate-900">{new Date(account.user.signup_date).toLocaleDateString()}</p>
                                            </div>
                                        )}
                                    </div>
                                </CardContent>
                            </Card>

                            {/* High Risk Accounts */}
                            <Card className="bg-white border-slate-200 shadow-sm">
                                <CardHeader>
                                    <CardTitle className="text-lg flex items-center gap-2 text-slate-900">
                                        <CreditCard className="h-5 w-5 text-slate-600" />
                                        High Risk Accounts ({account.high_risk_accounts?.length || 0})
                                    </CardTitle>
                                    <CardDescription className="text-slate-500">
                                        Accounts with risk score ≥ 50
                                    </CardDescription>
                                </CardHeader>
                                <CardContent>
                                    {account.high_risk_accounts && account.high_risk_accounts.length > 0 ? (
                                        <div className="space-y-4">
                                            {account.high_risk_accounts.map((acc: any) => {
                                                const accId = acc.id || acc['1'] || 'Unknown'
                                                const prediction = account.account_predictions?.find(p => p.account_id === accId)
                                                const isHighest = accId === account.highest_risk_account_id
                                                return (
                                                    <div 
                                                        key={accId} 
                                                        className={`p-4 rounded-lg border ${isHighest ? 'border-red-300 bg-red-50' : 'border-slate-200 bg-slate-50'}`}
                                                    >
                                                        <div className="flex items-center justify-between mb-3">
                                                            <div className="flex items-center gap-2">
                                                                <span className="font-semibold text-slate-900">{accId}</span>
                                                                {isHighest && (
                                                                    <span className="text-xs px-2 py-0.5 rounded bg-red-100 text-red-700 border border-red-200">
                                                                        HIGHEST RISK
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <div className="flex items-center gap-1">
                                                                <TrendingUp className="h-4 w-4 text-red-600" />
                                                                <span className="font-bold text-red-600">
                                                                    {prediction?.risk_score?.toFixed(1) ?? 'N/A'}
                                                                </span>
                                                            </div>
                                                        </div>
                                                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                                                            <div>
                                                                <span className="text-slate-500">Bank</span>
                                                                <p className="font-medium text-slate-900">{acc.bank_name || 'N/A'}</p>
                                                            </div>
                                                            <div>
                                                                <span className="text-slate-500">Type</span>
                                                                <p className="font-medium text-slate-900">{acc.type || 'N/A'}</p>
                                                            </div>
                                                            <div>
                                                                <span className="text-slate-500">Balance</span>
                                                                <p className="font-medium text-slate-900">{formatCurrency(acc.balance ?? 0)}</p>
                                                            </div>
                                                            <div>
                                                                <span className="text-slate-500">Status</span>
                                                                <p className="font-medium text-slate-900">{acc.status || 'N/A'}</p>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )
                                            })}
                                        </div>
                                    ) : (
                                        <div className="text-center text-slate-500 py-4">
                                            No high-risk accounts found
                                        </div>
                                    )}
                                </CardContent>
                            </Card>
                        </TabsContent>

                        {/* Investigation Tab - Shows report (progress is in Review Workflow on the right) */}
                        <TabsContent value="investigation" className="mt-6 space-y-6">
                            <InvestigationReport
                                userId={accountId}
                                finalAssessment={investigation.finalAssessment}
                                toolCalls={investigation.toolCalls}
                                agentIterations={investigation.agentIterations}
                                initialEvidence={investigation.initialEvidence}
                                completedSteps={investigation.completedSteps}
                                typology={investigation.typology}
                                risk={investigation.risk}
                                decision={investigation.decision}
                                report={investigation.report}
                                accountProfile={investigation.accountProfile}
                                networkEvidence={investigation.networkEvidence}
                            />
                            
                            {/* Graph visualization from investigation if available */}
                            {investigation.networkEvidence?.subgraph_nodes && investigation.networkEvidence.subgraph_nodes.length > 0 && (
                                <Card className="bg-white border-slate-200 shadow-sm">
                                    <CardHeader>
                                        <CardTitle className="text-lg text-slate-900">Investigation Network Graph</CardTitle>
                                        <CardDescription className="text-slate-500">
                                            Connections discovered during investigation
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="text-sm text-slate-500">
                                            {investigation.networkEvidence.subgraph_nodes.length} nodes, {investigation.networkEvidence.subgraph_edges?.length || 0} edges discovered
                                        </div>
                                        {/* You could render a graph here using the subgraph data */}
                                    </CardContent>
                                </Card>
                            )}
                        </TabsContent>

                        <TabsContent value="graph" className="mt-6">
                            <GraphVisualization accountId={accountId} />
                        </TabsContent>

                        <TabsContent value="transactions" className="mt-6">
                            <Card className="bg-white border-slate-200 shadow-sm">
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2 text-slate-900">
                                        <DollarSign className="h-5 w-5 text-slate-600" />
                                        Recent Transactions
                                    </CardTitle>
                                    <CardDescription className="text-slate-500">
                                        Showing transactions for highest risk account: <span className="font-medium text-slate-700">{account.highest_risk_account_id || 'N/A'}</span>
                                    </CardDescription>
                                </CardHeader>
                                <CardContent>
                                    {account.suspicious_transactions.length > 0 ? (
                                        <>
                                            <div className="space-y-3">
                                                {account.suspicious_transactions.map((txn) => (
                                                    <div key={txn.id} className="flex items-center justify-between p-4 border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors">
                                                        <div className="flex items-center gap-4">
                                                            <div className={`p-2 rounded-full ${
                                                                txn.risk === 'high' ? 'bg-red-100 text-red-600' :
                                                                txn.risk === 'medium' ? 'bg-amber-100 text-amber-600' :
                                                                'bg-green-100 text-green-600'
                                                            }`}>
                                                                <DollarSign className="h-4 w-4" />
                                                            </div>
                                                            <div>
                                                                <p className="font-medium text-slate-900">{txn.recipient}</p>
                                                                <div className="flex items-center gap-2 text-sm text-slate-500">
                                                                    <span>{txn.id}</span>
                                                                    <span>•</span>
                                                                    <span>{txn.type}</span>
                                                                    <span>•</span>
                                                                    <span>{new Date(txn.date).toLocaleDateString()}</span>
                                                                </div>
                                                            </div>
                                                        </div>
                                                        <div className="text-right">
                                                            <p className="text-lg font-semibold text-slate-900">{formatCurrency(txn.amount ?? 0)}</p>
                                                            <span className={`text-xs px-2 py-0.5 rounded border ${riskBadge(txn.risk || 'low')}`}>
                                                                {(txn.risk || 'low').toUpperCase()} RISK
                                                            </span>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                            <div className="mt-4 pt-4 border-t border-slate-200">
                                                <div className="flex justify-between items-center">
                                                    <span className="text-slate-500">Total Amount</span>
                                                    <span className="text-2xl font-bold text-red-600">
                                                        {formatCurrency(account.suspicious_transactions?.reduce((sum, t) => sum + (t.amount ?? 0), 0) ?? 0)}
                                                    </span>
                                                </div>
                                            </div>
                                        </>
                                    ) : (
                                        <div className="text-center text-slate-500 py-8">
                                            No transactions found for this account
                                        </div>
                                    )}
                                </CardContent>
                            </Card>
                        </TabsContent>

                        <TabsContent value="devices" className="mt-6">
                            <Card className="bg-white border-slate-200 shadow-sm">
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2 text-slate-900">
                                        <Smartphone className="h-5 w-5 text-slate-600" />
                                        Linked Devices
                                    </CardTitle>
                                    <CardDescription className="text-slate-500">
                                        Devices associated with this account
                                    </CardDescription>
                                </CardHeader>
                                <CardContent>
                                    {account.devices.length > 0 ? (
                                        <div className="space-y-3">
                                            {account.devices.map((device) => (
                                                <div key={device.id} className={`flex items-center justify-between p-4 border rounded-lg ${
                                                    !device.trusted ? 'border-amber-200 bg-amber-50' : 'border-slate-200'
                                                }`}>
                                                    <div className="flex items-center gap-4">
                                                        <div className={`p-2 rounded-full ${
                                                            device.trusted 
                                                                ? 'bg-green-100 text-green-600'
                                                                : 'bg-amber-100 text-amber-600'
                                                        }`}>
                                                            <Smartphone className="h-4 w-4" />
                                                        </div>
                                                        <div>
                                                            <div className="flex items-center gap-2">
                                                                <p className="font-medium text-slate-900">{device.type}</p>
                                                                {!device.trusted && (
                                                                    <span className="text-xs px-2 py-0.5 rounded bg-amber-100 text-amber-700 border border-amber-200">
                                                                        FLAGGED
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <div className="flex items-center gap-2 text-sm text-slate-500">
                                                                <span>{device.os}</span>
                                                                {device.location && device.location !== 'Unknown' && (
                                                                    <>
                                                                        <span>•</span>
                                                                        <span className="flex items-center gap-1">
                                                                            <MapPin className="h-3 w-3" />
                                                                            {device.location}
                                                                        </span>
                                                                    </>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div className="text-right text-sm text-slate-500">
                                                        <p>Last seen</p>
                                                        <p className="font-medium text-slate-900">
                                                            {device.last_seen ? new Date(device.last_seen).toLocaleDateString() : 'Unknown'}
                                                        </p>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="text-center text-slate-500 py-8">
                                            No devices found for this account
                                        </div>
                                    )}
                                </CardContent>
                            </Card>
                        </TabsContent>

                        <TabsContent value="activity" className="mt-6">
                            <Card className="bg-white border-slate-200 shadow-sm">
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2 text-slate-900">
                                        <Activity className="h-5 w-5 text-slate-600" />
                                        Recent Activity Log
                                    </CardTitle>
                                    <CardDescription className="text-slate-500">
                                        Activity timeline for highest risk account: <span className="font-medium text-slate-700">{account.highest_risk_account_id || 'N/A'}</span>
                                    </CardDescription>
                                </CardHeader>
                                <CardContent>
                                    {account.activity_log.length > 0 ? (
                                        <div className="space-y-4">
                                            {account.activity_log.map((activity, idx) => (
                                                <div key={idx} className="flex gap-4">
                                                    <div className="flex flex-col items-center">
                                                        <div className={`w-3 h-3 rounded-full ${
                                                            activity.status === 'alert' ? 'bg-red-500' :
                                                            activity.status === 'warning' ? 'bg-amber-500' :
                                                            activity.status === 'pending' ? 'bg-indigo-500' :
                                                            'bg-slate-400'
                                                        }`} />
                                                        {idx < account.activity_log.length - 1 && (
                                                            <div className="w-0.5 flex-1 bg-slate-200" />
                                                        )}
                                                    </div>
                                                    <div className="pb-4 flex-1">
                                                        <div className="flex items-center justify-between">
                                                            <p className="font-medium text-slate-900">{activity.action}</p>
                                                            {activity.amount != null && (
                                                                <span className="font-semibold text-slate-900">{formatCurrency(activity.amount ?? 0)}</span>
                                                            )}
                                                        </div>
                                                        <p className="text-sm text-slate-500">{activity.time}</p>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="text-center text-slate-500 py-8">
                                            No recent activity recorded
                                        </div>
                                    )}
                                </CardContent>
                            </Card>
                        </TabsContent>
                    </Tabs>
                </div>

                {/* Right Column - Workflow with AI Integration */}
                <div className="lg:col-span-1">
                    <ReviewWorkflow 
                        currentStep={currentStep}
                        onStepChange={setCurrentStep}
                        investigationStatus={investigation.status}
                        investigationSteps={investigation.steps}
                        completedInvestigationSteps={investigation.completedSteps}
                        currentNode={investigation.currentNode}
                        toolCalls={investigation.toolCalls}
                        traceEvents={investigation.traceEvents}
                        getStepStatus={investigation.getStepStatus}
                        accountPredictions={account.account_predictions || []}
                        highestRiskAccountId={account.highest_risk_account_id || ''}
                        existingResolutions={account.account_resolutions || {}}
                    />
                    
                    {/* Performance Metrics - shown after investigation runs */}
                    {(investigation.status === 'running' || investigation.status === 'completed') && investigation.performanceMetrics && (
                        <PerformanceMetricsPanel metrics={investigation.performanceMetrics} />
                    )}
                </div>
            </div>
        </div>
    )
}
