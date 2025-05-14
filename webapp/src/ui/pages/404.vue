<template>
  <div class="grid min-h-full place-items-center bg-white px-6 py-24 sm:py-32 lg:px-8">
    <div class="text-center">
      <p class="text-base font-semibold text-(--primary-color)">404</p>
      <h1 class="mt-4 text-balance text-5xl font-semibold tracking-tight text-gray-900 sm:text-7xl">Page not found</h1>
      <p class="mt-6 text-pretty text-lg font-medium text-gray-500 sm:text-xl/8">Sorry, we couldn' find the page you're looking for.</p>
      <div class="mt-10 flex items-center justify-center gap-x-6">
        <RouterLink to="/">
          <sl-button variant="primary">
            Go back home
          </sl-button>
        </RouterLink>
        <!-- <a href="#" class="rounded-md bg-(--primary-color) px-3.5 py-2.5 text-sm font-semibold text-white shadow-xs hover:bg-(--primary-color) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--primary-color)">Go back home</a> -->
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// import { ChevronRightIcon } from '@heroicons/vue/24/outline'
// import { BookmarkSquareIcon, BookOpenIcon, RssIcon, ListBulletIcon } from '@heroicons/vue/24/outline'

// props

// events

// composables

// lifecycle

// variables
// const links = [
//   { title: 'Documentation', description: 'Learn how to integrate our tools with your app', icon: BookOpenIcon },
//   { title: 'API Reference', description: 'A complete API reference for our libraries', icon: ListBulletIcon },
//   { title: 'Guides', description: 'Installation guides that cover popular setups', icon: BookmarkSquareIcon },
//   { title: 'Blog', description: 'Read our latest news and articles', icon: RssIcon },
// ];


// computed

// watch

// functions
</script>
