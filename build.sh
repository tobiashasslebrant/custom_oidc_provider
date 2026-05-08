dotnet package -c Release
rm deploy.zip
zip deploy.zip -r bin/Release/net10.0/publish/*

