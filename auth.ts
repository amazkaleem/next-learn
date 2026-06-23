import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";
import type { User } from "@/app/lib/definitions";
import bcrypt from "bcrypt";
import postgres from "postgres";

const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null; // Path 1: Valid (returns null)

          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) return user; // Path 2: Valid (returns User)
        }

        // Path 3: What if passwords DON'T match?
        // Path 4: What if parsedCredentials.success is FALSE?
        // Both Path 3 (bad password) and Path 4 (bad form data) land here:
        console.log("Invalid credentials");
        return null; // ✅ Explicitly returns null instead of undefined!
      },
    }),
  ],
});

/* 
NextAuth has a strict type contract for the authorize function. 
It expects you to return either a User object (success) or null (failure). 
It explicitly forbids returning undefined.
That is why when we comment out the following lines of code:
console.log("Invalid credentials");
return null;
Nextjs throws an error
*/
