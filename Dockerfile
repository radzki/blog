FROM ruby:3.2-slim

# Install essential build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /srv/jekyll

# Copy Gemfile first for better caching
COPY Gemfile ./

# Install bundler and gems
RUN gem install bundler && bundle install

# Expose Jekyll's default port
EXPOSE 4000

# Default command - serve with auto-regeneration
CMD ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0", "--force_polling", "--watch"]

