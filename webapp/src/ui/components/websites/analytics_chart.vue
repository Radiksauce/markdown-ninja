<template>
  <canvas id="visits_chart"></canvas>
</template>

<script lang="ts" setup>
import type { AnalyticsData } from '@/api/model';
import {
  Chart, LineController, LineElement, CategoryScale, LinearScale, PointElement, Tooltip, Filler,
} from 'chart.js';
import date from 'mdninja-js/src/libs/date';
import { onMounted, type PropType } from 'vue';

Chart.register(LineController, LineElement, CategoryScale, LinearScale, PointElement, Tooltip, Filler);


// props
const props = defineProps({
  data: {
    type: Object as PropType<AnalyticsData>,
    required: true,
  },
});

// events

// composables

// lifecycle


// variables
let chart: Chart | null = null;


// computed
onMounted(() => initChart());

// watch
window.addEventListener('resize', () => {
  if (chart) {
    chart!.resize();
    chart.render();
  }
}, true);


// functions

function initChart() {
  const ctx = (document.getElementById("visits_chart") as any).getContext("2d")!;


  const grandienPageViews = ctx.createLinearGradient(0, 0, 0, 350);
  // grandienPageViews.addColorStop(0, 'rgba(0, 0, 0, 0.18)');
  grandienPageViews.addColorStop(0, '#b8e6fe'); // sky-200
  grandienPageViews.addColorStop(1, '#ffffff');

  const gradientVisitors = ctx.createLinearGradient(0, 0, 0, 350);
  // gradientVisitors.addColorStop(0, 'rgba(0, 0, 0, 0.1)');
  // gradientVisitors.addColorStop(1, 'rgba(0, 0, 0, 0)');
  gradientVisitors.addColorStop(0, '#fff085'); // yellow-200
  gradientVisitors.addColorStop(1, '#ffffff');

  chart = new Chart(
    /* @ts-ignore */
    ctx,
    {
      type: 'line',
      data: {
        labels: props.data!.page_views.map(row => date(row.label, false)),
        datasets: [
          {
            label: 'Visitors',
            data: props.data!.visitors.map(row => row.count),
            borderColor: '#000',
            backgroundColor: gradientVisitors,
            fill: 'origin',
            pointRadius: 0,
            borderWidth: 1,
            tension: 0.3, // make the curve looks rounded instead of sharp
          },
          {
            label: 'Page views',
            data: props.data!.page_views.map(row => row.count),
            borderColor: '#000',
            backgroundColor: grandienPageViews,
            fill: 'origin',
            pointRadius: 0,
            borderWidth: 1,
            tension: 0.3, // make the curve looks rounded instead of sharp
          },
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        // more details if want to draw a vertical line for the tooltip
        // https://stackoverflow.com/questions/45159895/moving-vertical-line-when-hovering-over-the-chart-using-chart-js
        interaction: {
          mode: 'index',
          intersect: false,
        },
        scales: {
          x: {
            // stacked: true,
            grid: {
              display: false
            },
            ticks: {
              // reduce the number of ticks (labels) of the X axis
              callback: function(value, index, _ticks) {
                  return index % 2 === 0 ? null : this.getLabelForValue(value as number);
              }
            }
          },
          y: {
            beginAtZero: true,
            grid: {
              display: false
            },
            ticks: {
              // reduce the number of ticks (labels) of the Y axis
              callback: function(value, index, _ticks) {
                  return index % 2 === 0 ? null : value;
              }
            }
          }
        },
        plugins: {
          tooltip: {
            // make page views appear before visitors in the tooltip
            itemSort: (a, b) => { return b.datasetIndex; },
            intersect: false,
            displayColors: false,
            position: 'nearest',
          }
        }
      },
    },
  );
}
</script>
