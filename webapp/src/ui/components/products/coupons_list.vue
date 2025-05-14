<template>
  <div class="-my-2 overflow-x-auto min-w-full">
    <sl-input :value="searchQuery" @input="searchQuery = $event.target.value.trim()" required placeholder="Search" />
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="table min-w-full divide-y divide-gray-200">
          <thead class="table-header-group bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Code
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Discount
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <RouterLink :to="couponUrl(coupon.id)" v-for="coupon in filteredCoupons" :key="coupon.id"
              class="table-row cursor-pointer min-w-full">
              <div class="table-cell px-6 py-4 whitespace-nowrap max-w-0 w-full">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ coupon.code }}
                </div>
              </div>
              <div class="table-cell mx-3 px-8 py-4 whitespace-nowrap">
                <span>{{ coupon.discount }}%</span>
              </div>
              <div class="table-cell px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200" v-if="coupon.archived">
                  Archived
                </span>
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800" v-else>
                  Active
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
import { ref, type PropType, computed } from 'vue';
import { useRoute } from 'vue-router';
import type { Coupon } from '@/api/model';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props
const props = defineProps({
  coupons: {
    type: Array as PropType<Coupon[]>,
    required: true,
  },
})

// events

// composables
const $route = useRoute();

// lifecycle

// variables
const websiteId = $route.params.website_id;
let searchQuery = ref('');

// computed
const filteredCoupons = computed((): Coupon[] => {
  return props.coupons.filter((coupon) => {
    return coupon.code.toLowerCase().includes(searchQuery.value.toLowerCase());
  });
})

// watch

// functions
function couponUrl(id: string): string {
  return `/websites/${websiteId}/coupons/${id}`;
}
</script>
