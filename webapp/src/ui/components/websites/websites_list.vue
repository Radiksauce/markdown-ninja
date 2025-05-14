<template>
  <div>
    <ul role="list" class="divide-y divide-neutral-100 overflow-hidden bg-white border rounded-xl border-gray-300">
      <li v-for="website in websites" :key="website.id" class="relative flex">
        <RouterLink :to="`/websites/${website.id}`"
          class="flex w-full justify-between group h-full px-4 py-5 gap-x-6 hover:bg-gray-50 sm:px-6">
          <div class="flex gap-x-4">
            <!-- <img class="h-12 w-12 flex-none rounded-full bg-gray-50" :src="person.imageUrl" alt="" /> -->
            <div class="min-w-0 flex-auto">
              <p class="text-sm font-medium leading-6 text-(--primary-color)">
                {{ website.name }}
              </p>
              <p class="mt-1 flex text-xs leading-5 text-neutral-500 group-hover:text-(--primary-color)">
                <span class="relative truncate">{{ website.primary_domain }}</span>
              </p>
            </div>
          </div>
          <div class="flex items-center gap-x-4 group-hover:text-(--primary-color) text-gray-400">
            <ChevronRightIcon class="h-5 w-5 flex-none" aria-hidden="true" />
          </div>
        </RouterLink>
      </li>
    </ul>
  </div>
</template>

<script lang="ts" setup>
import type { Website } from '@/api/model';
import { ChevronRightIcon } from '@heroicons/vue/24/outline'
import type { PropType } from 'vue';

// props
defineProps({
  websites: {
    type: Array as PropType<Website[]>,
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
