'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { X, ArrowLeft, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useDebounce } from '@/hooks/useDebounce'
import SearchResults, { SearchResultsProps } from './SearchResults'

interface FullScreenSearchProps {
  isOpen: boolean
  onClose: () => void
}

export function FullScreenSearch({ isOpen, onClose }: FullScreenSearchProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const debouncedSearchQuery = useDebounce(searchQuery, 300)
  const router = useRouter()

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = 'unset'
    }
    return () => {
      document.body.style.overflow = 'unset'
    }
  }, [isOpen])

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value)
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      router.push(`/search?q=${encodeURIComponent(searchQuery.trim())}`)
      onClose()
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-background z-50 overflow-y-auto">
      <div className="container mx-auto px-4 py-8">
        <div className="flex justify-between items-center mb-8">
          <Button variant="ghost" size="icon" onClick={onClose}>
            <ArrowLeft className="h-6 w-6" />
            <span className="sr-only">Back</span>
          </Button>
          <Button variant="ghost" size="icon" onClick={() => setSearchQuery('')}>
            <X className="h-6 w-6" />
            <span className="sr-only">Clear search</span>
          </Button>
        </div>
        <form onSubmit={handleSearchSubmit} className="mb-8">
          <div className="relative">
            <Input
              type="search"
              placeholder="Search..."
              className="w-full text-2xl py-6 pl-12 pr-4"
              value={searchQuery}
              onChange={handleSearchChange}
              autoFocus
            />
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 h-6 w-6 text-muted-foreground" />
          </div>
        </form>
        {debouncedSearchQuery && (
          <SearchResults 
            query={debouncedSearchQuery} 
            mode="full" 
            onResultClick={(slug) => {
              router.push(`/blog/${slug}`)
              onClose()
            }}
            key={debouncedSearchQuery} 
          />
        )}
      </div>
    </div>
  )
}

