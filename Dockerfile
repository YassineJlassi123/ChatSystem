# Use the official .NET 8 SDK image as the base image
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the csproj and restore as distinct layers
COPY *.csproj ./
RUN dotnet restore

# Copy the rest of the application code
COPY . ./

# Build the application
RUN dotnet publish -c Release -o out

# Use the official .NET 8 ASP.NET image as the base image for runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime

# Set the working directory inside the container
WORKDIR /app

# Copy the build artifacts from the build image
COPY --from=build /app/out .

# Expose the port the app runs on
EXPOSE 80

# Define the entry point for the container
ENTRYPOINT ["dotnet", "jwtlogin.dll"]
