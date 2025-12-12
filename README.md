# RE://notes

> Notes from (reverse) engineering

A cyberpunk-themed blog built with Jekyll and hosted on GitHub Pages.

## 🚀 Quick Start

### Using Docker (Recommended)

The easiest way to run locally — no Ruby installation required:

```bash
# Build and start the container
docker-compose up

# Visit http://localhost:4000
```

The site will auto-reload when you make changes.

### Using Ruby directly

If you prefer running Jekyll natively:

```bash
# Install dependencies
bundle install

# Serve locally with live reload
bundle exec jekyll serve --livereload

# Visit http://localhost:4000
```

## 📝 Creating Posts

Posts live in the `_posts` directory. Create a new file with the format:

```
_posts/YYYY-MM-DD-title-of-post.md
```

Each post needs front matter:

```yaml
---
layout: post
title: "Your Post Title"
description: "A brief description"
date: YYYY-MM-DD
tags: [tag1, tag2]
---

Your content here...
```

### Drafts

Work on posts without publishing them by creating files in `_drafts`:

```
_drafts/my-work-in-progress.md
```

View drafts locally with:

```bash
docker-compose up  # drafts are enabled by default
# or
bundle exec jekyll serve --drafts
```

## 🎨 Customization

### Site Settings

Edit `_config.yml` to change:

- `title` — Your blog name
- `description` — Tagline shown on homepage
- `author` — Your name
- `url` — Your site's URL (for production)

### Styling

The theme is in `assets/css/main.css`. Key CSS variables:

```css
:root {
  --accent-primary: #00ff9f;    /* Main accent (terminal green) */
  --accent-secondary: #0ff;      /* Secondary (cyan) */
  --bg-main: #0d0d12;           /* Background */
  /* ... more in the file */
}
```

### Layouts

- `_layouts/default.html` — Base template
- `_layouts/home.html` — Homepage
- `_layouts/post.html` — Blog posts
- `_layouts/page.html` — Static pages

## 🌐 Deployment

The site auto-deploys to GitHub Pages when you push to `main`.

### First-time setup

1. Go to your repo's **Settings → Pages**
2. Under "Build and deployment", select **GitHub Actions**
3. Push to `main` — the workflow will build and deploy automatically

Your site will be live at: `https://yourusername.github.io/blog`

## 📁 Structure

```
.
├── _config.yml          # Site configuration
├── _layouts/            # HTML templates
├── _posts/              # Blog posts (YYYY-MM-DD-title.md)
├── _drafts/             # Unpublished drafts
├── assets/
│   └── css/
│       └── main.css     # Styles
├── about.md             # About page
├── index.html           # Homepage
├── Dockerfile           # Docker config
├── docker-compose.yml   # Docker Compose config
├── Gemfile              # Ruby dependencies
└── README.md            # This file
```

## 📜 License

Content is yours. The theme/code is MIT licensed — use it however you want.
