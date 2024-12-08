import { Suspense } from 'react'
import SearchResults from '@/components/SearchResults'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export default function SearchPage({
  searchParams
}: {
  searchParams: { q: string }
}) {
  const query = searchParams.q

  return (
    <div className="w-full px-4 sm:px-6 lg:px-8 py-8">
      <h1 className="text-3xl font-bold mb-8">Search Results for &quot;{query}&quot;</h1>
      <Suspense fallback={
        <div className="flex justify-center items-center py-8">
          <LoadingSpinner size="large" />
        </div>
      }>
        <SearchResults query={query} mode="full" />
      </Suspense>
    </div>
  )
}

