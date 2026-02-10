@echo off
echo Testing company login...
curl -X POST http://localhost:3000/api/company-login ^
  -H "Content-Type: application/json" ^
  -H "X-Company-Key: test" ^
  -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
pause
