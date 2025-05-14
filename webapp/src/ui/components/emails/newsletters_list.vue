<template>
  <div class="-my-2 overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="table min-w-full divide-y divide-gray-200">
          <thead class="table-header-group bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Subject
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Date
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <RouterLink :to="`./newsletters/${newsletter.id}`" v-for="newsletter in newsletters" :key="newsletter.id"
              class="table-row cursor-pointer min-w-full">
              <div class="table-cell px-6 py-4 whitespace-nowrap max-w-0 w-full">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ newsletter.subject }}
                </div>
              </div>
              <div class="table-cell mx-3 px-8 py-4 whitespace-nowrap">
                <div class="text-sm text-gray-900" v-if="newsletter.sent_at">{{ date(newsletter.sent_at) }}</div>
                <div class="text-sm text-gray-900" v-else-if="newsletter.scheduled_for">{{ date(newsletter.scheduled_for) }}</div>
                <div class="text-sm text-gray-900" v-else>-</div>
              </div>
              <div class="table-cell px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800" v-if="newsletter.sent_at">
                  Sent
                </span>
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800" v-else-if="newsletter.scheduled_for">
                  Scheduled
                </span>
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200" v-else>
                  Draft
                </span>
              </div>
            </RouterLink>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { NewsletterMetadata } from '@/api/model';
import { type PropType } from 'vue';
import date from 'mdninja-js/src/libs/date';

// props
defineProps({
  newsletters: {
    type: Array as PropType<NewsletterMetadata[]>,
    required: true,
  },
})

// events

// composables

// lifecycle

// variables


// computed

// watch

// functions
</script>
