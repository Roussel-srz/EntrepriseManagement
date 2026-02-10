@echo off
echo Testing company registration...
curl -X POST http://localhost:3000/api/register-company ^
  -H "Content-Type: application/json" ^
  -d "{\"companyKey\":\"test\",\"companyName\":\"Test Enterprise\",\"adminEmail\":\"test@test.com\"}"
pause
