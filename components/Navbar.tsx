'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Menu, Search, Phone } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { ThemeToggle } from '@/components/theme-toggle'
import { useAuth } from '@/contexts/AuthContext'
import { FullScreenSearch } from './FullScreenSearch'
import { Input } from '@/components/ui/input'
import { LoadingOverlay } from '@/components/LoadingOverlay' // Import LoadingOverlay

const getNavItems = (isAuthenticated: boolean, isAdmin: boolean) => [
  { name: 'Home', href: '/' },
  { name: 'Blog', href: '/blog' },
  { name: 'About', href: '/about' },
  ...(isAuthenticated
    ? [
        {
          name: 'Dashboard',
          href: '/admin/dashboard',
        },
        {
          name: 'Manage Posts',
          href: '/admin/dashboard/manage-posts',
        },
        {
          name: 'Create Post',
          href: '/admin/dashboard/create-post',
        },
      ]
    : []),
]

export function Navbar() {
  const [isSearchOpen, setIsSearchOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false) // Added loading state
  const pathname = usePathname()
  const { isAuthenticated, user, logout } = useAuth()
  const isAdmin = user?.role === 'admin'
  const navItems = getNavItems(isAuthenticated, isAdmin)

  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b bg-background">
        <div className="container mx-auto px-4">
          <div className="flex h-16 items-center justify-between gap-4">
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" className="md:hidden">
                  <Menu className="h-6 w-6" />
                  <span className="sr-only">Open menu</span>
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-[300px] sm:w-[400px]">
                <nav className="flex flex-col space-y-4">
                  {navItems.map((item) => (
                    <Button
                      key={item.name}
                      variant="ghost"
                      className={`justify-start ${pathname === item.href ? 'bg-muted' : ''}`}
                      asChild
                    >
                      <Link href={item.href}>{item.name}</Link>
                    </Button>
                  ))}
                  {isAuthenticated ? (
                    <Button variant="ghost" className="justify-start" onClick={() => logout()}>Logout</Button>
                  ) : (
                    <Button variant="ghost" className="justify-start" asChild>
                      <Link href="/admin">Login</Link>
                    </Button>
                  )}
                </nav>
              </SheetContent>
            </Sheet>

            <div className="relative w-full max-w-sm">
              <Input
                type="search"
                placeholder="Search..."
                className="pl-10"
                onClick={() => setIsSearchOpen(true)}
              />
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            </div>

            <nav className="hidden md:flex space-x-4 items-center">
              {navItems.map((item) => (
                <Button
                  key={item.name}
                  variant="ghost"
                  className={pathname === item.href ? 'bg-muted' : ''}
                  asChild
                >
                  <Link href={item.href}>{item.name}</Link>
                </Button>
              ))}
              {isAuthenticated ? (
                <Button variant="ghost" onClick={() => logout()}>Logout</Button>
              ) : (
                <Button variant="ghost" asChild>
                  <Link href="/admin">Login</Link>
                </Button>
              )}
            </nav>

            <div className="flex items-center space-x-4">
              <Button variant="ghost" size="icon" asChild>
                <a href="tel:+1234567890">
                  <Phone className="h-6 w-6" />
                  <span className="sr-only">Call us</span>
                </a>
              </Button>
              <ThemeToggle />
            </div>
          </div>
        </div>
      </header>
      <FullScreenSearch 
        isOpen={isSearchOpen} 
        onClose={() => {
          setIsSearchOpen(false)
          setIsLoading(false)
        }} 
      />
      {isLoading && <LoadingOverlay />} {/* Added LoadingOverlay */}
    </>
  )
}

