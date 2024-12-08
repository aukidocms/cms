'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export interface SearchResult {
  id: number;
  title: string;
  content: string;
  slug: string;
  tags: string[];
}

export interface SearchResultsProps {
  query: string;
  mode?: 'live' | 'full';
  onResultClick?: (slug: string) => void; // Updated interface
}

export default function SearchResults({ query, mode = 'full', onResultClick }: SearchResultsProps) {
  const [searchResults, setSearchResults] = useState<SearchResult[]>([])
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    const fetchSearchResults = async () => {
      if (!query) {
        setSearchResults([])
        return
      }

      setIsLoading(true)
      try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`)
        if (response.ok) {
          const data = await response.json()
          setSearchResults(data)
        } else {
          console.error('Failed to fetch search results')
        }
      } catch (error) {
        console.error('Error fetching search results:', error)
      } finally {
        setIsLoading(false)
      }
    }

    fetchSearchResults()
  }, [query])


  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-8">
        <LoadingSpinner size="large" />
      </div>
    )
  }

  if (searchResults.length === 0) {
    return <p className="text-center py-4 text-lg text-muted-foreground">No results found for "{query}"</p>
  }

  return (
    <div className="space-y-4">
      {searchResults.map((post) => (
        <Card key={post.id}>
          <CardHeader>
            <CardTitle>
              <Link
                href={`/blog/${post.slug}`}
                className="hover:underline"
                onClick={(e) => {
                  e.preventDefault();
                  onResultClick?.(post.slug); // Updated onClick handler
                }}
              >
                {post.title}
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground mb-2">
              {post.content.length > 200
                ? `${post.content.substring(0, 200)}...`
                : post.content}
            </p>
            <div className="flex flex-wrap gap-2">
              {post.tags && post.tags.map((tag) => (
                <Badge key={tag} variant="secondary">
                  {tag}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

