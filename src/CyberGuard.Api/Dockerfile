FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY CyberGuard.sln ./
COPY src/CyberGuard.Domain/CyberGuard.Domain.csproj src/CyberGuard.Domain/
COPY src/CyberGuard.Application/CyberGuard.Application.csproj src/CyberGuard.Application/
COPY src/CyberGuard.Infrastructure/CyberGuard.Infrastructure.csproj src/CyberGuard.Infrastructure/
COPY src/CyberGuard.Shared/CyberGuard.Shared.csproj src/CyberGuard.Shared/
COPY src/CyberGuard.Api/CyberGuard.Api.csproj src/CyberGuard.Api/
RUN dotnet restore src/CyberGuard.Api/CyberGuard.Api.csproj

COPY src/ src/
RUN dotnet publish src/CyberGuard.Api/CyberGuard.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "CyberGuard.Api.dll"]
