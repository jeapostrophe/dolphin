#pragma once

namespace Libretro
{
namespace Video
{
namespace Vk
{
// create_device_wrapper is the frontend's CreateDevice wrapper from the v2
// context negotiation interface, or NULL when negotiating v1; see the warped
// vkCreateDevice in Vulkan.cpp.
void Init(VkInstance instance, VkPhysicalDevice gpu, VkSurfaceKHR surface,
          PFN_vkGetInstanceProcAddr get_instance_proc_addr, const char** required_device_extensions,
          unsigned num_required_device_extensions, const char** required_device_layers,
          unsigned num_required_device_layers, const VkPhysicalDeviceFeatures* required_features,
          retro_vulkan_create_device_wrapper_t create_device_wrapper, void* opaque);
// Drops the wrapper and opaque stored by Init. They are the frontend's, and are
// only valid for the duration of the negotiation call that handed them over, so
// the caller of Init forgets them as soon as it returns; after that the warped
// vkCreateDevice is back to calling the real one.
void ForgetCreateDeviceWrapper();
void SetSurfaceSize(uint32_t width, uint32_t height);
void SetHWRenderInterface(retro_hw_render_interface* hw_render_interface);
void Shutdown();
void WaitForPresentation();
VkSurfaceKHR GetSurface();
}  // namespace Vk
}  // namespace Video
}  // namespace Libretro
