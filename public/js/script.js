const carousel = document.getElementById("carousel");
const cards = carousel.querySelectorAll(".card");
let currentCardIndex = 0;
const totalCards = cards.length;
let rotationInterval = null;
let isPopupOpen = false;

// Dynamische stappen en afstand op basis van scherm
function getResponsiveSettings() {
  const width = window.innerWidth;

  if (width <= 400) return { rotationStep: 45, radius: 160 }; // Zeer compact
  if (width <= 600) return { rotationStep: 50, radius: 200 }; // Mobiel
  if (width <= 768) return { rotationStep: 60, radius: 260 }; // Tablet
  return { rotationStep: 72, radius: 350 }; // Desktop
}

function setCardPositions() {
  const { rotationStep, radius } = getResponsiveSettings();
  cards.forEach((card, i) => {
    const rotateY = i * rotationStep;
    const angleRad = (rotateY * Math.PI) / 180;
    const x = Math.sin(angleRad) * radius;
    const z = Math.cos(angleRad) * radius;
    card.style.transform = `translateX(${x}px) translateZ(${z}px) rotateY(${rotateY}deg)`;
  });
  rotateCarousel(); // herbereken rotatiehoek bij aanpassing
  updateCardSize();
}

function updateCardSize() {
  cards.forEach((card, i) => {
    if (i === currentCardIndex) {
      card.style.transform += " scale(1.2)";
      card.style.zIndex = "1";
    } else {
      card.style.transform = card.style.transform.replace(" scale(1.2)", "");
      card.style.zIndex = "0";
    }
  });
}

function rotateCarousel() {
  const { rotationStep } = getResponsiveSettings();
  const rotateDeg = -rotationStep * currentCardIndex;
  carousel.style.transform = `rotateY(${rotateDeg}deg)`;
}

function startRotation() {
  if (rotationInterval || isPopupOpen) return;
  rotationInterval = setInterval(() => {
    currentCardIndex = (currentCardIndex + 1) % totalCards;
    setCardPositions();
  }, 1400);
}

function stopRotation() {
  if (rotationInterval) {
    clearInterval(rotationInterval);
    rotationInterval = null;
  }
}

carousel.addEventListener("mouseover", () => {
  if (!isPopupOpen) stopRotation();
});

carousel.addEventListener("mouseout", () => {
  if (!isPopupOpen) startRotation();
});

carousel.addEventListener("touchstart", () => {
  if (!isPopupOpen) stopRotation();
});

carousel.addEventListener("touchend", () => {
  if (!isPopupOpen) startRotation();
});

function showPopup(cardId) {
  const popup = document.getElementById(`popup-${cardId}`);
  if (popup) {
    popup.classList.add("show");
    isPopupOpen = true;
    stopRotation();
  }
}

function closePopup() {
  document.querySelectorAll(".popup").forEach((popup) => {
    popup.classList.remove("show");
  });
  isPopupOpen = false;
  startRotation();
}

cards.forEach((card) => {
  card.addEventListener("click", () => {
    const cardId = card.dataset.id;
    showPopup(cardId);
  });
});

// Init + resize support
setCardPositions();
startRotation();

window.addEventListener("resize", () => {
  setCardPositions(); // opnieuw positioneren bij vensterverandering
});
            