//
//  GameState.swift
//  Ultimate Noughts and Crosses
//
//  Created by Kyle Jessup on 2015-10-28.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//

enum PlayerType {
	case Ex, Oh, None
}

class GameState {
	var boards = [[PlayerType]]()
	
	init() {
		for _ in 0..<9 {
			var sub = [PlayerType]()
			for _ in 0..<9 {
				sub.append(.None)
			}
			self.boards.append(sub)
		}
	}
}

