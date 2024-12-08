import React from 'react'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export function LoadingOverlay() {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <LoadingSpinner size="large" />
    </div>
  )
}

