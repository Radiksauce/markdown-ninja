<template>
  <div class="bg-white">
    <div class="mx-auto max-w-7xl px-6 lg:px-8">
      <div class="mx-auto  sm:text-center">
        <h2 class="mt-2 text-5xl font-semibold tracking-tight">
          Everything you need in one place.
          <!-- Superpowers for creators -->
        </h2>
        <p class="mt-6 text-lg leading-8">
          Focus on creating great content, we take care of all the technical details.
          <!-- <br /> -->
          <!-- Less is more. -->
        </p>
      </div>
    </div>
    <!-- <div class="relative overflow-hidden pt-16">
      <div class="mx-auto max-w-7xl px-6 lg:px-8">
        <img src="/webapp/about/app_screenshot.png" alt="App screenshot" class="mb-[-12%] rounded-xl shadow-2xl ring-1 ring-gray-900/10" width="2432" height="1442" />
        <div class="relative" aria-hidden="true">
          <div class="absolute -inset-x-20 bottom-0 bg-gradient-to-t from-white pt-[7%]" />
        </div>
      </div>
    </div> -->
    <div class="mx-auto mt-18 max-w-7xl px-6 lg:px-8">
      <dl class="mx-auto grid max-w-2xl grid-cols-1 gap-x-6 gap-y-10 text-base leading-7 sm:grid-cols-2 lg:mx-0 lg:max-w-none lg:grid-cols-3 lg:gap-x-8 lg:gap-y-16">
        <div v-for="feature in features" :key="feature.name" class="relative pl-9">
          <dt class="flex items-center font-semibold">
            <div class="flex size-8 items-center justify-center rounded-full bg-neutral-100">
              <component :is="feature.icon" class="size-5" aria-hidden="true" />
            </div>
            <span class="ml-4">
              {{ feature.name }}
            </span>
          </dt>
          {{ ' ' }}
          <dd class="" v-html="feature.description"></dd>
        </div>
      </dl>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { useConfig } from '@/app/config';
import {
  PresentationChartLineIcon,
  ShieldCheckIcon,
  LockClosedIcon,
  GlobeEuropeAfricaIcon,
  CodeBracketIcon,
  MagnifyingGlassIcon,
} from '@heroicons/vue/24/outline';

// props

// events

// composables
const $config = useConfig();

// lifecycle

// variables
const features = [
  {
    name: 'Optimized for SEO and Humans',
    description: `Markdown Ninja uses server-side and client-side rendering to offer
      first-class experience for both Humans and SEO. With built-in RSS feeds, of course.`,
    icon: MagnifyingGlassIcon,
  },
  {
    name: 'Built-in Analytics',
    description: `Stop paying for 10 different services just to know what are your most popular pages with our private-by-design
      server-side analytics.`,
    icon: PresentationChartLineIcon,
  },
  {
    name: 'GDPR & CCPA Compliant',
    description: `Markdown Ninja is built to respect your audience and maintain their trust.
      You don't need to send their data to 745 'partners' with our unified platform.`,
    icon: ShieldCheckIcon,
  },
  {
    name: 'Secure by design',
    description: `While search engine bots are welcome in exchange for traffic, bad bots and hackers are kept outside.
      The time of your website being hacked due to outdated plugins is long gone.`,
    icon: LockClosedIcon,
  },
  {
    name: 'Simple and Sustainable',
    description: `Markdown is the most pragmatic and interoperable format ever. Edit your posts in your
      favorite editor from any device and publish in 1 click to your global audience.
      Need more convincing? Markdown Ninja is
      <a href="${$config.githubRepository}" target="_blank" rel="noopener" class="underline">Open Source</a>`,
    icon: GlobeEuropeAfricaIcon,
  },
  // {
  //   name: 'Headless CMS',
  //   description: `Do you have a rockstar frontend team? Keep your content and your optimized Markdown workflow
  //     with any framework thanks to Markdown Ninja's easy-to-use headless API.`,
  //   icon: CodeBracketIcon,
  // },
  {
    name: 'No Plugins',
    description: `Don't lose your precious time configuring 20+ plugins and cleaning up your site after a hack due to an outdated plugin.
      Markdown Ninja includes everything you need to build and grow you audience.`,
    icon: CodeBracketIcon,
  },
];

// computed

// watch

// functions
</script>
