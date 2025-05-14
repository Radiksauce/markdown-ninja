<template>
    <ul class="px-0 mx-0">
      <li class="flex flex-col" v-for="(post, _index) in pages" :key="post.path">
        <RouterLink :to="post.path" class="py-4 rounded-[4px] text-md bg-[var(--mdninja-background)] hover:brightness-[0.95] w-full hover:no-underline px-2 flex flex-col sm:flex-row justify-between">
          <span class="flex">{{ post.title }}</span>
          <span class="flex pt-3 sm:pt-0 sm:pl-3 min-w-max">
            <time :datetime="date(post.date)" class="text-[#8f8f8f] text-lg">
              {{ date(post.date, false) }}
            </time>
          </span>
        </RouterLink>
      </li>
    </ul>
</template>

<script lang="ts" setup>
import date from '@/libs/date';
import type { PageMetadata } from '@/app/model';
import { type PropType } from 'vue';

// props
defineProps({
  pages: {
    type: Array as PropType<PageMetadata[]>,
    required: true,
  },
});

// events

// composables

// lifecycle
// variables

// computed

// watch

// functions
</script>
