TOKEN=$(curl -s -X POST https://chat.demo.altinity.cloud/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"btyshkevich@gmail.com","password":"korokino"}' \
  | jq -r '.token')

curl 'https://chat.demo.altinity.cloud/api/agents/agent_boTt3weAG__GDzZ6oK62_' \
  -X 'PATCH' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json' \
  -b '_clck=17ohvia%7C2%7Cfwo%7C0%7C1955; refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NDk3MzJkMzYxMzI1ZTI2MmFiNmUyMiIsInNlc3Npb25JZCI6IjY4NDk3MzQ2MzYxMzI1ZTI2MmFiNmUyOCIsImlhdCI6MTc0OTY1NzY4NywiZXhwIjoxNzUwMjQ4OTAxfQ.3AucprQe4heLOlYj4GUJjrZPNY6ABbQ06eBjKhDv0-8' \
  -H 'Origin: https://chat.demo.altinity.cloud' \
  -H 'Referer: https://chat.demo.altinity.cloud/c/b5c1e67a-9582-49b0-86d5-ec2db17f04f9' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"name":"github","artifacts":"","description":"","instructions":"","model":"claude-opus-4-20250514","tools":["discover_data_mcp_mcp-test","list_tables_mcp_mcp-test","query_mcp_mcp-test"],"provider":"anthropic","agent_ids":[],"end_after_tools":false,"hide_sequential_outputs":false, "shared": true}' | jq


curl 'https://chat.demo.altinity.cloud/api/roles/user/agents' \
  -X 'PUT' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NDk3MzJkMzYxMzI1ZTI2MmFiNmUyMiIsInVzZXJuYW1lIjoiYnZ0IiwicHJvdmlkZXIiOiJsb2NhbCIsImVtYWlsIjoiYnR5c2hrZXZpY2hAZ21haWwuY29tIiwiaWF0IjoxNzQ5NjU4NjE1LCJleHAiOjE3NDk2NTk1MTV9.Cpb3GzA842sa7rFYuNbOlz3kXr2Sq1vpEaoO8_rTHlQ' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json' \
  -b '_clck=17ohvia%7C2%7Cfwo%7C0%7C1955; refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NDk3MzJkMzYxMzI1ZTI2MmFiNmUyMiIsInNlc3Npb25JZCI6IjY4NDk3MzQ2MzYxMzI1ZTI2MmFiNmUyOCIsImlhdCI6MTc0OTY1ODYxNSwiZXhwIjoxNzUwMjQ4OTAyfQ.4hRnOtnuL-1jz0UVv9oskgvBUhw9XuWBy16wuVmnBgg' \
  -H 'Origin: https://chat.demo.altinity.cloud' \
  -H 'Referer: https://chat.demo.altinity.cloud/c/b5c1e67a-9582-49b0-86d5-ec2db17f04f9' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"SHARED_GLOBAL":true,"USE":true,"CREATE":false}'
  curl 'https://chat.demo.altinity.cloud/api/roles/user/agents' \
  -X 'PUT' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NDk3MzJkMzYxMzI1ZTI2MmFiNmUyMiIsInVzZXJuYW1lIjoiYnZ0IiwicHJvdmlkZXIiOiJsb2NhbCIsImVtYWlsIjoiYnR5c2hrZXZpY2hAZ21haWwuY29tIiwiaWF0IjoxNzQ5NjU5NTYwLCJleHAiOjE3NDk2NjA0NjB9.J_J20eG8PcrbWaFVkyG8KB-sRJcHMbbXVr0liLyo_aE' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json' \
  -b '_clck=17ohvia%7C2%7Cfwo%7C0%7C1955; refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NDk3MzJkMzYxMzI1ZTI2MmFiNmUyMiIsInNlc3Npb25JZCI6IjY4NDk3MzQ2MzYxMzI1ZTI2MmFiNmUyOCIsImlhdCI6MTc0OTY1OTU2MCwiZXhwIjoxNzUwMjQ4OTAyfQ._uJa0uroHruVJK38ppP0p_taHNdSLSwYVskJA29wMGE' \
  -H 'Origin: https://chat.demo.altinity.cloud' \
  -H 'Referer: https://chat.demo.altinity.cloud/c/b5c1e67a-9582-49b0-86d5-ec2db17f04f9' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"SHARED_GLOBAL":true,"USE":true,"CREATE":true}'


  curl 'https://chat.demo.altinity.cloud/api/agents/agent_boTt3weAG__GDzZ6oK62_' \
  -X 'PATCH' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NDk3MzJkMzYxMzI1ZTI2MmFiNmUyMiIsInVzZXJuYW1lIjoiYnZ0IiwicHJvdmlkZXIiOiJsb2NhbCIsImVtYWlsIjoiYnR5c2hrZXZpY2hAZ21haWwuY29tIiwiaWF0IjoxNzQ5NjU4NjE1LCJleHAiOjE3NDk2NTk1MTV9.Cpb3GzA842sa7rFYuNbOlz3kXr2Sq1vpEaoO8_rTHlQ' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json' \
  -b '_clck=17ohvia%7C2%7Cfwo%7C0%7C1955; refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4NDk3MzJkMzYxMzI1ZTI2MmFiNmUyMiIsInNlc3Npb25JZCI6IjY4NDk3MzQ2MzYxMzI1ZTI2MmFiNmUyOCIsImlhdCI6MTc0OTY1ODYxNSwiZXhwIjoxNzUwMjQ4OTAyfQ.4hRnOtnuL-1jz0UVv9oskgvBUhw9XuWBy16wuVmnBgg' \
  -H 'Origin: https://chat.demo.altinity.cloud' \
  -H 'Referer: https://chat.demo.altinity.cloud/c/b5c1e67a-9582-49b0-86d5-ec2db17f04f9' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  --data-raw '{"name":"github","artifacts":"default","description":"","instructions":"","model":"claude-opus-4-20250514","tools":["discover_data_mcp_mcp-test","list_tables_mcp_mcp-test","query_mcp_mcp-test"],"provider":"anthropic","agent_ids":[],"end_after_tools":false,"hide_sequential_outputs":false}'