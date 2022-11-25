# Build stage
FROM node:lts as builder

# Set directory and copy source code
WORKDIR /app
COPY yarn.lock package.json ./

# Install dependencies
RUN yarn install

# Bundle app source
COPY . .

# Build app
RUN yarn build

# Production stage
FROM nginx:stable-alpine as production

# Set working directory
WORKDIR /usr/share/nginx/html

# Remove default nginx static assets
RUN rm -rf ./*

# Copy static assets from the build stage
COPY --from=builder /app/build .

# Expose port 80
EXPOSE 80

# Run nginx
CMD ["nginx", "-g", "daemon off;"]
