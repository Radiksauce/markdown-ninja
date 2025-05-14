<template>
  <div>
    <ul role="list" class="divide-y divide-neutral-100 overflow-hidden bg-white border rounded-xl border-gray-300">
      <li v-for="organization in organizations" :key="organization.id" class="relative flex">
        <RouterLink :to="`/organizations/${organization.id}`"
          class="flex w-full justify-between group h-full px-4 py-5 gap-x-6 hover:bg-gray-50 sm:px-6">
          <div class="flex gap-x-4">
            <div class="min-w-0 flex-auto">
              <p class="text-sm font-medium leading-6">
                {{ organization.name }}
              </p>
            </div>
          </div>
          <div class="flex items-center gap-x-4 text-neutral-400 group-hover:text-(--primary-color)">
            <ChevronRightIcon class="h-5 w-5 flex-none" aria-hidden="true" />
          </div>
        </RouterLink>
      </li>
    </ul>
  </div>
</template>

<script lang="ts" setup>
import type { Organization } from '@/api/model';
import { ChevronRightIcon } from '@heroicons/vue/24/outline'
import type { PropType } from 'vue';

// props
defineProps({
  organizations: {
    type: Array as PropType<Organization[]>,
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
