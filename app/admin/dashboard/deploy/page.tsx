'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { toast } from '@/components/ui/use-toast'
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { AlertCircle, Rocket } from 'lucide-react'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export default function DeployPage() {
  const [isLoading, setIsLoading] = useState(true)
  const [isDeploying, setIsDeploying] = useState(false)
  const [lastDeployment, setLastDeployment] = useState<string | null>(null)
  const router = useRouter()

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/auth/me', { 
          credentials: 'include',
          headers: {
            'Cache-Control': 'no-cache',
          },
        });
        if (response.ok) {
          // Fetch last deployment info here
          // For now, we'll just set it to null
          setLastDeployment(null)
          setIsLoading(false)
        } else {
          router.push('/admin');
        }
      } catch (error) {
        console.error('Error checking authentication:', error);
        router.push('/admin');
      }
    };

    checkAuth();
  }, [router]);

  const handleDeploy = async () => {
    setIsDeploying(true)
    try {
      const response = await fetch('/api/deploy', {
        method: 'POST',
        credentials: 'include',
      })

      if (!response.ok) {
        throw new Error('Deployment failed')
      }

      const data = await response.json()
      
      toast({
        title: "Success",
        description: data.message || "Deployment triggered successfully",
      })
      setLastDeployment(new Date().toISOString())
    } catch (error) {
      console.error('Deployment error:', error)
      toast({
        title: "Error",
        description: "Failed to trigger deployment. Please try again.",
        variant: "destructive",
      })
    } finally {
      setIsDeploying(false)
    }
  }

  if (isLoading) {
    return (
      <div className="container mx-auto py-10 flex justify-center items-center min-h-[calc(100vh-4rem)]">
        <LoadingSpinner size="large" />
      </div>
    );
  }

  return (
    <div className="container mx-auto py-10">
      <Card className="max-w-2xl mx-auto">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Rocket className="h-6 w-6" />
            Deploy and Redeploy
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Important</AlertTitle>
            <AlertDescription>
              Triggering a deployment will update your live site on Vercel with the latest changes.
              Make sure all your changes are committed and pushed to the main branch.
              You can also use this to redeploy your site if needed.
            </AlertDescription>
          </Alert>
          {lastDeployment ? (
            <p className="text-sm text-muted-foreground">
              Last deployment: {new Date(lastDeployment).toLocaleString()}
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">No recent deployments</p>
          )}
        </CardContent>
        <CardFooter>
          <Button onClick={handleDeploy} disabled={isDeploying}>
            {isDeploying ? (
              <>
                <LoadingSpinner size="small" className="mr-2" />
                Deploying...
              </>
            ) : (
              'Deploy / Redeploy'
            )}
          </Button>
        </CardFooter>
      </Card>
    </div>
  )
}

