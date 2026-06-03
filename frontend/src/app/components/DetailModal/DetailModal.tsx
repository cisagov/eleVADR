import React from "react";
import "./DetailModal.css";

interface DetailModalProps {
  isOpen: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}

const DetailModal: React.FC<DetailModalProps> = ({
  isOpen,
  title,
  onClose,
  children,
}) => {
  if (!isOpen) return null;

  return (
    <div className="detail-modal-overlay" onClick={onClose}>
      <div
        className="detail-modal"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="detail-modal-header">
          <h2>{title}</h2>
          <button
            type="button"
            className="detail-modal-close"
            onClick={onClose}
          >
            ×
          </button>
        </div>
        <div className="detail-modal-body">{children}</div>
      </div>
    </div>
  );
};

export default DetailModal;
