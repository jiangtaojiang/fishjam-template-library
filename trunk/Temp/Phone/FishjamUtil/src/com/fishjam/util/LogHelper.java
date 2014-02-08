package com.fishjam.util;

import android.R.integer;
import android.graphics.Matrix;
import android.graphics.PointF;
import android.text.method.MovementMethod;
import android.view.KeyEvent;
import android.view.MotionEvent;

public final class LogHelper {
	
	public static String FormatPointF(PointF pointF){
		StringBuilder sBuilder = new StringBuilder();
		sBuilder.append(pointF.x + "," + pointF.y);
		return sBuilder.toString();
	}
	
	public static String FormatMatrix(Matrix matrix) {
		StringBuilder sBuilder = new StringBuilder();
		if (matrix != null) {
			float[] matrixValues = new float[9];
			matrix.getValues(matrixValues);
			for (int i = 0; i < 3; ++i) {
				for (int j = 0; j < 3; ++j) {
					sBuilder.append(matrixValues[3 * i + j] + ",");
				}
				if (i < 2) {
					sBuilder.append("    ");
				}
			}
		}
		return sBuilder.toString();
	}
	
	public static String FormatMotionEvent(MotionEvent event){
		StringBuilder sBuilder = new StringBuilder();
		int nAction = event.getAction() & MotionEvent.ACTION_MASK;
		switch(nAction) {
		case MotionEvent.ACTION_DOWN:
			sBuilder.append("ACTION_DOWN: " + event.getX() + "," + event.getY() + ",PointerCount=" + event.getPointerCount());
			break;
		case MotionEvent.ACTION_UP:
			sBuilder.append("ACTION_UP: " + event.getX() + "," + event.getY() + ",PointerCount=" + event.getPointerCount());
			break;
		case MotionEvent.ACTION_MOVE:
			sBuilder.append("ACTION_MOVE: " + event.getX() + "," + event.getY() + ",PointerCount=" + event.getPointerCount());
			break;
		case MotionEvent.ACTION_CANCEL:
			sBuilder.append("ACTION_CANCEL");
			break;
		case MotionEvent.ACTION_OUTSIDE:
			sBuilder.append("ACTION_OUTSIDE");
			break;
		case MotionEvent.ACTION_POINTER_DOWN:
			sBuilder.append("ACTION_POINTER_DOWN: " + event.getX(1) + "," + event.getY(1) + ",PointerCount=" + event.getPointerCount());
			break;
		case MotionEvent.ACTION_POINTER_UP:
			sBuilder.append("ACTION_POINTER_UP: " + event.getX(1) + "," + event.getY(1) + ",PointerCount=" + event.getPointerCount());
			break;
//		case MotionEvent.ACTION_HOVER_MOVE:
//			sBuilder.append("ACTION_HOVER_MOVE");
//			break;
//		case MotionEvent.ACTION_SCROLL:
//			sBuilder.append("ACTION_SCROLL");
//			break;
//		case MotionEvent.ACTION_HOVER_ENTER:
//			sBuilder.append("ACTION_HOVER_ENTER");
//			break;
//		case MotionEvent.ACTION_HOVER_EXIT:
//			sBuilder.append("ACTION_HOVER_EXIT");
//			break;
		default:
			sBuilder.append("Unknown=" + nAction);
			break;
		}
		return sBuilder.toString();
	}
	
	public static String FormatKeyEvent(KeyEvent event){
		StringBuilder sBuilder = new StringBuilder();
		switch(event.getAction()) {
		case KeyEvent.ACTION_DOWN:
			sBuilder.append("Down");
			break;
		case KeyEvent.ACTION_MULTIPLE:
			sBuilder.append("Multiple");
			break;
		case KeyEvent.ACTION_UP:
			sBuilder.append("Up");
			break;
		}
		return sBuilder.toString();
	}
	
}
