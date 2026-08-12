import type { User } from "./types.ts"

// Demo users — passwords stored as plain text for demo clarity only
const users: User[] = [
  {
    id: "user-1",
    username: "alice",
    passwordHash: "password123",
    name: "Alice Smith",
    email: "alice@example.com",
  },
  {
    id: "user-2",
    username: "bob",
    passwordHash: "password456",
    name: "Bob Jones",
    email: "bob@example.com",
  },
]

export function findUserByCredentials(username: string, password: string): User | null {
  return users.find(u => u.username === username && u.passwordHash === password) ?? null
}

export function findUserById(id: string): User | null {
  return users.find(u => u.id === id) ?? null
}
