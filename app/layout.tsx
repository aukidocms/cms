'use client'

import { Inter } from 'next/font/google'
import '@/app/globals.css'
import { Navbar } from '@/components/Navbar'
import { Footer } from '@/components/Footer'
import { AuthProvider } from '@/contexts/AuthContext'
import { ThemeProvider } from "@/components/theme-provider"
import { Toaster } from "@/components/ui/toaster"
// import { useEffect, useState } from 'react'
import LoadingOverlay from '@/components/LoadingOverlay'; // Assuming LoadingOverlay component exists

const inter = Inter({ subsets: ['latin'] })

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  // const [isLoading, setIsLoading] = useState(true)

  // useEffect(() => {
  //   setIsLoading(false)
  // }, [])

  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.className} flex flex-col min-h-screen`}>
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
          <AuthProvider>
            <Navbar />
            <main className="flex-grow pt-4">{children}</main>
            <Footer />
            <Toaster />
          </AuthProvider>
        </ThemeProvider>
        {/* <LoadingOverlay isLoading={isLoading} /> */}
      </body>
    </html>
  )
}

