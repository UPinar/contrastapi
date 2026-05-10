document.addEventListener("DOMContentLoaded", function () {
  var btn = document.getElementById("crypto-checkout-btn");
  if (!btn) return;
  btn.addEventListener("click", async function () {
    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Creating invoice…";
    try {
      var r = await fetch("/v1/billing/crypto/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!r.ok) throw new Error("checkout failed: " + r.status);
      var d = await r.json();
      if (!d.invoice_url) throw new Error("missing invoice_url");
      window.location.href = d.invoice_url;
    } catch (e) {
      btn.disabled = false;
      btn.textContent = original;
      alert("Crypto checkout temporarily unavailable. Please use the card option or contact support.");
    }
  });
});
