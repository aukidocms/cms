export const runtime = 'nodejs'
import { NextResponse } from 'next/server';
import { db } from '@/src/db';
import { users, NewUser } from '@/src/db/schema';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcryptjs';

export async function POST(request: Request) {
  try {
    const body: NewUser = await request.json();
    
    // Check if user already exists
    const existingUser = await db.select().from(users).where(eq(users.email, body.email)).limit(1);
    if (existingUser.length > 0) {
      return NextResponse.json({ error: 'User already exists' }, { status: 400 });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(body.password, 10);

    // Create new user
    const newUser = await db.insert(users).values({
      ...body,
      password: hashedPassword,
    }).returning();
    
    // Remove password from the response
    const { password, ...userWithoutPassword } = newUser[0];
    
    return NextResponse.json(userWithoutPassword, { status: 201 });
  } catch (error) {
    console.error('Error registering user:', error);
    return NextResponse.json({ error: 'Error registering user' }, { status: 500 });
  }
}

