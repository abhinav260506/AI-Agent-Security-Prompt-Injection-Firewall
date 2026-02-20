// vite.config.js
import { defineConfig } from "file:///C:/Users/abhin/Desktop/promt_cns/surgical-guard/node_modules/vite/dist/node/index.js";
import react from "file:///C:/Users/abhin/Desktop/promt_cns/surgical-guard/node_modules/@vitejs/plugin-react/dist/index.js";
import { crx } from "file:///C:/Users/abhin/Desktop/promt_cns/surgical-guard/node_modules/@crxjs/vite-plugin/dist/index.mjs";

// manifest.json
var manifest_default = {
  manifest_version: 3,
  name: "Surgical-Guard",
  version: "1.0.0",
  description: "AI Safety Firewall against indirect prompt injections",
  permissions: [
    "activeTab",
    "scripting",
    "storage",
    "sidePanel"
  ],
  host_permissions: [
    "<all_urls>"
  ],
  action: {
    default_popup: "index.html"
  },
  background: {
    service_worker: "src/background/service-worker.js",
    type: "module"
  },
  content_scripts: [
    {
      matches: [
        "<all_urls>"
      ],
      js: [
        "src/content/content-script.js"
      ],
      run_at: "document_end"
    }
  ]
};

// vite.config.js
var vite_config_default = defineConfig({
  plugins: [
    react(),
    crx({ manifest: manifest_default })
  ]
});
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcuanMiLCAibWFuaWZlc3QuanNvbiJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiY29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2Rpcm5hbWUgPSBcIkM6XFxcXFVzZXJzXFxcXGFiaGluXFxcXERlc2t0b3BcXFxccHJvbXRfY25zXFxcXHN1cmdpY2FsLWd1YXJkXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ZpbGVuYW1lID0gXCJDOlxcXFxVc2Vyc1xcXFxhYmhpblxcXFxEZXNrdG9wXFxcXHByb210X2Nuc1xcXFxzdXJnaWNhbC1ndWFyZFxcXFx2aXRlLmNvbmZpZy5qc1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vQzovVXNlcnMvYWJoaW4vRGVza3RvcC9wcm9tdF9jbnMvc3VyZ2ljYWwtZ3VhcmQvdml0ZS5jb25maWcuanNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tICd2aXRlJ1xyXG5pbXBvcnQgcmVhY3QgZnJvbSAnQHZpdGVqcy9wbHVnaW4tcmVhY3QnXHJcbmltcG9ydCB7IGNyeCB9IGZyb20gJ0Bjcnhqcy92aXRlLXBsdWdpbidcclxuaW1wb3J0IG1hbmlmZXN0IGZyb20gJy4vbWFuaWZlc3QuanNvbidcclxuXHJcbi8vIGh0dHBzOi8vdml0ZWpzLmRldi9jb25maWcvXHJcbmV4cG9ydCBkZWZhdWx0IGRlZmluZUNvbmZpZyh7XHJcbiAgcGx1Z2luczogW1xyXG4gICAgcmVhY3QoKSxcclxuICAgIGNyeCh7IG1hbmlmZXN0IH0pLFxyXG4gIF0sXHJcbn0pXHJcbiIsICJ7XHJcbiAgICBcIm1hbmlmZXN0X3ZlcnNpb25cIjogMyxcclxuICAgIFwibmFtZVwiOiBcIlN1cmdpY2FsLUd1YXJkXCIsXHJcbiAgICBcInZlcnNpb25cIjogXCIxLjAuMFwiLFxyXG4gICAgXCJkZXNjcmlwdGlvblwiOiBcIkFJIFNhZmV0eSBGaXJld2FsbCBhZ2FpbnN0IGluZGlyZWN0IHByb21wdCBpbmplY3Rpb25zXCIsXHJcbiAgICBcInBlcm1pc3Npb25zXCI6IFtcclxuICAgICAgICBcImFjdGl2ZVRhYlwiLFxyXG4gICAgICAgIFwic2NyaXB0aW5nXCIsXHJcbiAgICAgICAgXCJzdG9yYWdlXCIsXHJcbiAgICAgICAgXCJzaWRlUGFuZWxcIlxyXG4gICAgXSxcclxuICAgIFwiaG9zdF9wZXJtaXNzaW9uc1wiOiBbXHJcbiAgICAgICAgXCI8YWxsX3VybHM+XCJcclxuICAgIF0sXHJcbiAgICBcImFjdGlvblwiOiB7XHJcbiAgICAgICAgXCJkZWZhdWx0X3BvcHVwXCI6IFwiaW5kZXguaHRtbFwiXHJcbiAgICB9LFxyXG4gICAgXCJiYWNrZ3JvdW5kXCI6IHtcclxuICAgICAgICBcInNlcnZpY2Vfd29ya2VyXCI6IFwic3JjL2JhY2tncm91bmQvc2VydmljZS13b3JrZXIuanNcIixcclxuICAgICAgICBcInR5cGVcIjogXCJtb2R1bGVcIlxyXG4gICAgfSxcclxuICAgIFwiY29udGVudF9zY3JpcHRzXCI6IFtcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIFwibWF0Y2hlc1wiOiBbXHJcbiAgICAgICAgICAgICAgICBcIjxhbGxfdXJscz5cIlxyXG4gICAgICAgICAgICBdLFxyXG4gICAgICAgICAgICBcImpzXCI6IFtcclxuICAgICAgICAgICAgICAgIFwic3JjL2NvbnRlbnQvY29udGVudC1zY3JpcHQuanNcIlxyXG4gICAgICAgICAgICBdLFxyXG4gICAgICAgICAgICBcInJ1bl9hdFwiOiBcImRvY3VtZW50X2VuZFwiXHJcbiAgICAgICAgfVxyXG4gICAgXVxyXG59Il0sCiAgIm1hcHBpbmdzIjogIjtBQUEyVSxTQUFTLG9CQUFvQjtBQUN4VyxPQUFPLFdBQVc7QUFDbEIsU0FBUyxXQUFXOzs7QUNGcEI7QUFBQSxFQUNJLGtCQUFvQjtBQUFBLEVBQ3BCLE1BQVE7QUFBQSxFQUNSLFNBQVc7QUFBQSxFQUNYLGFBQWU7QUFBQSxFQUNmLGFBQWU7QUFBQSxJQUNYO0FBQUEsSUFDQTtBQUFBLElBQ0E7QUFBQSxJQUNBO0FBQUEsRUFDSjtBQUFBLEVBQ0Esa0JBQW9CO0FBQUEsSUFDaEI7QUFBQSxFQUNKO0FBQUEsRUFDQSxRQUFVO0FBQUEsSUFDTixlQUFpQjtBQUFBLEVBQ3JCO0FBQUEsRUFDQSxZQUFjO0FBQUEsSUFDVixnQkFBa0I7QUFBQSxJQUNsQixNQUFRO0FBQUEsRUFDWjtBQUFBLEVBQ0EsaUJBQW1CO0FBQUEsSUFDZjtBQUFBLE1BQ0ksU0FBVztBQUFBLFFBQ1A7QUFBQSxNQUNKO0FBQUEsTUFDQSxJQUFNO0FBQUEsUUFDRjtBQUFBLE1BQ0o7QUFBQSxNQUNBLFFBQVU7QUFBQSxJQUNkO0FBQUEsRUFDSjtBQUNKOzs7QUQxQkEsSUFBTyxzQkFBUSxhQUFhO0FBQUEsRUFDMUIsU0FBUztBQUFBLElBQ1AsTUFBTTtBQUFBLElBQ04sSUFBSSxFQUFFLDJCQUFTLENBQUM7QUFBQSxFQUNsQjtBQUNGLENBQUM7IiwKICAibmFtZXMiOiBbXQp9Cg==
