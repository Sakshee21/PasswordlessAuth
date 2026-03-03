
import React, { useState } from 'react';
import { Info, X } from 'lucide-react';

interface InfoTooltipProps {
  title: string;
  content: string;
}

export const InfoTooltip: React.FC<InfoTooltipProps> = ({ title, content }) => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="relative inline-block ml-2 align-middle">
      <button 
        onClick={() => setIsOpen(!isOpen)}
        className="p-1 rounded-full bg-slate-100 hover:bg-slate-200 transition-colors"
      >
        <Info size={14} className="text-slate-500" />
      </button>
      
      {isOpen && (
        <div className="absolute z-50 w-64 p-4 mt-2 bg-white border border-slate-200 rounded-lg shadow-xl right-0 md:left-0 md:right-auto">
          <div className="flex justify-between items-start mb-2">
            <h4 className="font-semibold text-sm text-slate-800">{title}</h4>
            <button onClick={() => setIsOpen(false)}><X size={14} /></button>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">{content}</p>
        </div>
      )}
    </div>
  );
};
