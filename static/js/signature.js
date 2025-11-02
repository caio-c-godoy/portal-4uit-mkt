
function enableSignatureCanvas(canvas){
  if(!canvas){ console.error('Signature canvas not found'); return; }
  const ctx = canvas.getContext('2d');
  let drawing = false, last = null;

  const pos = (e)=>{
    const rect = canvas.getBoundingClientRect();
    if(e.touches && e.touches[0]){
      return { x: e.touches[0].clientX - rect.left, y: e.touches[0].clientY - rect.top };
    }else if(e.clientX!=null){
      return { x: e.clientX - rect.left, y: e.clientY - rect.top };
    }else if(e.offsetX!=null){
      return { x: e.offsetX, y: e.offsetY };
    }
    return null;
  };

  const start = (e)=>{
    const p = pos(e);
    if(!p) return;
    drawing = true; last = p;
  };
  const move = (e)=>{
    if(!drawing) return;
    const p = pos(e);
    if(!p) return;
    ctx.lineWidth=2; ctx.lineCap='round'; ctx.strokeStyle='#111827';
    ctx.beginPath(); ctx.moveTo(last.x,last.y); ctx.lineTo(p.x,p.y); ctx.stroke();
    last = p;
    e.preventDefault?.();
  };
  const end = ()=>{ drawing=false; };

  // Pointer events
  canvas.addEventListener('pointerdown', start);
  canvas.addEventListener('pointermove', move);
  window.addEventListener('pointerup', end);

  // Mouse fallback
  canvas.addEventListener('mousedown', start);
  canvas.addEventListener('mousemove', move);
  window.addEventListener('mouseup', end);

  // Touch fallback
  canvas.addEventListener('touchstart', start, {passive:false});
  canvas.addEventListener('touchmove', move, {passive:false});
  window.addEventListener('touchend', end);
}
