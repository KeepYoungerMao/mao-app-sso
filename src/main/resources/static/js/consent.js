/**
 * 授权确认页交互：点击“拒绝授权”时清空所有 scope 勾选，
 * 使表单以空 scope 提交（客户端将收到 error=access_denied）。
 * 不使用内联事件处理器，符合 CSP script-src 'self' 约束。
 */
(function () {
  'use strict';
  document.addEventListener('DOMContentLoaded', function () {
    var denyButton = document.getElementById('deny-button');
    if (!denyButton) {
      return;
    }
    denyButton.addEventListener('click', function () {
      var checkboxes = document.querySelectorAll('input[name="scope"]');
      for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = false;
      }
    });
  });
})();
