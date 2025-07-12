// cart.js
// Handles cart add/remove and undo functionality using localStorage

document.addEventListener('DOMContentLoaded', function() {
  // Add to Cart buttons
  const addToCartButtons = [
    ...document.querySelectorAll('.add-to-cart'),
    ...document.querySelectorAll('.snack-item .add-to-cart'),
    ...document.querySelectorAll('.pickle-item .add-to-cart')
  ];
  addToCartButtons.forEach(function(btn) {
    btn.addEventListener('click', function() {
      const itemDiv = btn.closest('.pickle-item') || btn.closest('.snack-item');
      const name = itemDiv.querySelector('h3').innerText;
      const price = itemDiv.querySelector('.price').innerText;
      addToCart({ name, price });
      showUndo(name);
    });
  });

  // Undo button (dynamically created)
  function showUndo(itemName) {
    let undoDiv = document.getElementById('undo-div');
    if (!undoDiv) {
      undoDiv = document.createElement('div');
      undoDiv.id = 'undo-div';
      undoDiv.style.position = 'fixed';
      undoDiv.style.bottom = '30px';
      undoDiv.style.right = '30px';
      undoDiv.style.background = '#4682B4';
      undoDiv.style.color = 'white';
      undoDiv.style.padding = '1rem 2rem';
      undoDiv.style.borderRadius = '8px';
      undoDiv.style.boxShadow = '2px 2px 10px #b0e0e6';
      document.body.appendChild(undoDiv);
    }
    undoDiv.innerHTML = `Added <b>${itemName}</b> to cart. <button id="undo-btn" style="margin-left:1rem;background:#2E8B57;color:white;border:none;padding:0.3rem 1rem;border-radius:5px;cursor:pointer;">Undo</button>`;
    document.getElementById('undo-btn').onclick = function() {
      removeFromCart(itemName);
      undoDiv.remove();
    };
    setTimeout(() => { if (undoDiv) undoDiv.remove(); }, 5000);
  }

  // Cart functions
  function getCart() {
    return JSON.parse(localStorage.getItem('cart') || '[]');
  }
  function setCart(cart) {
    localStorage.setItem('cart', JSON.stringify(cart));
  }
  function addToCart(item) {
    const cart = getCart();
    const existingItem = cart.find(i => i.name === item.name);
    if (!existingItem) {
      cart.push(item);
      setCart(cart);
    }
  }
  function removeFromCart(itemName) {
    let cart = getCart();
    cart = cart.filter(i => i.name !== itemName);
    setCart(cart);
    if (window.location.pathname.includes('cart')) {
      location.reload();
    }
  }
  
  // Make functions globally available
  window.addToCart = addToCart;
  window.removeFromCart = removeFromCart;
});
