"use server";
// app/api/route.js
import { Client } from 'pg';
import dotenv from 'dotenv';
dotenv.config();
const client = new Client({
  connectionString: process.env.DATABASE_URL,
});
client.connect();
export async function GET() {
  try {
    const result = await client.query('SELECT * FROM tbl_users');
    return new Response(JSON.stringify(result.rows), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
      },
    });
  } catch (error) {

    return new Response(JSON.stringify({ error: "Internal Server Error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
